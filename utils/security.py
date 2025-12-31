"""
Modbus Firewall - Security Policy Engine

Implements security policies including whitelist/blacklist, time-based rules,
IP filtering, and rate limiting.
"""

import time
from dataclasses import dataclass
from typing import Dict, Set, Optional, Tuple
from datetime import datetime, time as dt_time
from collections import defaultdict
from enum import Enum

from core.config import DEFAULT_CONFIG, SecurityPolicy, ModbusFunctionCode, get_function_code_name
from utils.dpi_engine import ModbusTCPFrame


class PolicyDecision(Enum):
    """Policy evaluation result"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    RATE_LIMITED = "RATE_LIMITED"


@dataclass
class PolicyResult:
    """Result of a policy evaluation"""
    decision: PolicyDecision
    reason: str
    
    @property
    def is_allowed(self) -> bool:
        return self.decision == PolicyDecision.ALLOW


class RateLimiter:
    """Token bucket rate limiter per client IP"""
    
    def __init__(self, rate_limit: int):
        self.rate_limit = rate_limit
        self.tokens: Dict[str, float] = defaultdict(lambda: float(rate_limit))
        self.last_update: Dict[str, float] = defaultdict(time.time)
    
    def check(self, client_ip: str) -> bool:
        """Check if request is within rate limit"""
        current_time = time.time()
        
        # Refill tokens based on time elapsed
        elapsed = current_time - self.last_update[client_ip]
        self.tokens[client_ip] = min(
            self.rate_limit,
            self.tokens[client_ip] + elapsed * self.rate_limit
        )
        self.last_update[client_ip] = current_time
        
        # Check if we have tokens
        if self.tokens[client_ip] >= 1:
            self.tokens[client_ip] -= 1
            return True
        return False
    
    def reset(self, client_ip: str):
        """Reset rate limiter for a client"""
        self.tokens[client_ip] = float(self.rate_limit)
        self.last_update[client_ip] = time.time()


class MaintenanceWindow:
    """Time-based maintenance window for allowing write operations"""
    
    def __init__(self):
        self.enabled = False
        self.start_time: Optional[dt_time] = None
        self.end_time: Optional[dt_time] = None
        self.allowed_days: Set[int] = set()  # 0=Monday, 6=Sunday
    
    def set_window(self, start: dt_time, end: dt_time, days: Set[int] = None):
        """Set maintenance window"""
        self.start_time = start
        self.end_time = end
        self.allowed_days = days or {0, 1, 2, 3, 4, 5, 6}  # All days by default
        self.enabled = True
    
    def disable(self):
        """Disable maintenance window"""
        self.enabled = False
    
    def is_active(self) -> bool:
        """Check if currently in maintenance window"""
        if not self.enabled:
            return False
        
        now = datetime.now()
        current_time = now.time()
        current_day = now.weekday()
        
        if current_day not in self.allowed_days:
            return False
        
        if self.start_time <= self.end_time:
            return self.start_time <= current_time <= self.end_time
        else:
            # Handle overnight windows (e.g., 22:00 - 06:00)
            return current_time >= self.start_time or current_time <= self.end_time


class SecurityPolicyEngine:
    """Main security policy enforcement engine"""
    
    def __init__(self, config: SecurityPolicy = None):
        self.config = config or DEFAULT_CONFIG.security
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        self.maintenance_window = MaintenanceWindow()
        
        # Manual override mode (allows all traffic)
        self.bypass_mode = False
        
        # Statistics
        self.stats = {
            'allowed': 0,
            'blocked': 0,
            'rate_limited': 0,
        }
    
    def evaluate(
        self,
        frame: ModbusTCPFrame,
        client_ip: str
    ) -> PolicyResult:
        """
        Evaluate a Modbus frame against security policies.
        
        Args:
            frame: Parsed Modbus TCP frame
            client_ip: Source IP address of the client
            
        Returns:
            PolicyResult with decision and reason
        """
        # Bypass mode - allow everything (for testing)
        if self.bypass_mode:
            self.stats['allowed'] += 1
            return PolicyResult(PolicyDecision.ALLOW, "Bypass mode enabled")
        
        # Rate limiting check
        if not self.rate_limiter.check(client_ip):
            self.stats['rate_limited'] += 1
            return PolicyResult(
                PolicyDecision.RATE_LIMITED,
                f"Rate limit exceeded for {client_ip}"
            )
        
        fc = frame.function_code
        fc_name = get_function_code_name(fc)
        
        # Check if function code is in whitelist
        if fc in self.config.allowed_function_codes:
            # Read operations are allowed by default
            self.stats['allowed'] += 1
            return PolicyResult(PolicyDecision.ALLOW, f"{fc_name} is whitelisted")
        
        # Check if function code is explicitly blocked
        if fc in self.config.blocked_function_codes:
            # Check for exceptions
            
            # 1. Check IP whitelist for write operations
            if frame.is_write_operation and client_ip in self.config.write_allowed_ips:
                self.stats['allowed'] += 1
                return PolicyResult(
                    PolicyDecision.ALLOW,
                    f"{fc_name} allowed for authorized IP {client_ip}"
                )
            
            # 2. Check maintenance window
            if frame.is_write_operation and self.maintenance_window.is_active():
                self.stats['allowed'] += 1
                return PolicyResult(
                    PolicyDecision.ALLOW,
                    f"{fc_name} allowed during maintenance window"
                )
            
            # 3. Check register-level policies
            if self.config.register_policies:
                from utils.dpi_engine import DPIEngine
                dpi = DPIEngine()
                register_addr = dpi.get_register_address(frame)
                if register_addr is not None and register_addr in self.config.register_policies:
                    if fc in self.config.register_policies[register_addr]:
                        self.stats['allowed'] += 1
                        return PolicyResult(
                            PolicyDecision.ALLOW,
                            f"{fc_name} allowed for register {register_addr}"
                        )
            
            # Block the request
            self.stats['blocked'] += 1
            return PolicyResult(
                PolicyDecision.BLOCK,
                f"{fc_name} (FC:0x{fc:02X}) is blocked by security policy"
            )
        
        # Unknown function codes - default deny
        self.stats['blocked'] += 1
        return PolicyResult(
            PolicyDecision.BLOCK,
            f"Unknown function code {fc_name} (FC:0x{fc:02X}) - default deny"
        )
    
    def add_write_allowed_ip(self, ip: str):
        """Add an IP to the write-allowed list"""
        self.config.write_allowed_ips.add(ip)
    
    def remove_write_allowed_ip(self, ip: str):
        """Remove an IP from the write-allowed list"""
        self.config.write_allowed_ips.discard(ip)
    
    def set_maintenance_window(self, start: dt_time, end: dt_time, days: Set[int] = None):
        """Set maintenance window for allowing writes"""
        self.maintenance_window.set_window(start, end, days)
    
    def disable_maintenance_window(self):
        """Disable maintenance window"""
        self.maintenance_window.disable()
    
    def enable_bypass(self):
        """Enable bypass mode (allow all traffic)"""
        self.bypass_mode = True
    
    def disable_bypass(self):
        """Disable bypass mode"""
        self.bypass_mode = False
    
    def add_register_policy(self, register: int, allowed_fcs: Set[int]):
        """Add register-level policy"""
        self.config.register_policies[register] = allowed_fcs
    
    def remove_register_policy(self, register: int):
        """Remove register-level policy"""
        self.config.register_policies.pop(register, None)
    
    def get_stats(self) -> dict:
        """Get policy enforcement statistics"""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'allowed': 0,
            'blocked': 0,
            'rate_limited': 0,
        }
    
    def get_policy_summary(self) -> str:
        """Get a human-readable summary of current policies with local/remote sections"""
        from core.config import DEFAULT_CONFIG
        
        local_policy = DEFAULT_CONFIG.local_security
        remote_policy = DEFAULT_CONFIG.remote_security
        
        lines = [
            "[bold cyan]Security Policy Summary[/bold cyan]",
            "",
            "[green]━━━ LOCAL + REMOTE ADMIN ━━━[/green]",
            "[dim]Full access for local users and authenticated remote admins[/dim]",
            "",
            "[green]Allowed:[/green]",
        ]
        
        for fc in sorted(local_policy.allowed_function_codes):
            lines.append(f"  ✓ 0x{fc:02X}: {get_function_code_name(fc)}")
        
        lines.append("")
        lines.append("[red]Blocked:[/red]")
        for fc in sorted(local_policy.blocked_function_codes):
            lines.append(f"  ✗ 0x{fc:02X}: {get_function_code_name(fc)}")
        
        lines.append("")
        lines.append("[yellow]━━━ REMOTE READ-ONLY ━━━[/yellow]")
        lines.append("[dim]Non-authenticated remote users[/dim]")
        lines.append("")
        lines.append("[green]Allowed:[/green]")
        
        for fc in sorted(remote_policy.readonly_function_codes):
            lines.append(f"  ✓ 0x{fc:02X}: {get_function_code_name(fc)}")
        
        lines.append("")
        lines.append("[red]Blocked (all writes):[/red]")
        
        # All write operations are blocked for read-only
        write_codes = {0x05, 0x06, 0x0F, 0x10, 0x17}
        for fc in sorted(write_codes):
            lines.append(f"  ✗ 0x{fc:02X}: {get_function_code_name(fc)}")
        
        return "\n".join(lines)
