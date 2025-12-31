"""
Modbus Firewall - Logging System

File-based logging for forensic analysis with real-time console output.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from core.config import DEFAULT_CONFIG, get_function_code_name


class LogAction(Enum):
    """Log action types"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ERROR = "ERROR"
    INFO = "INFO"
    ALERT = "ALERT"


@dataclass
class LogEntry:
    """Represents a single log entry"""
    timestamp: str
    transaction_id: int
    source_ip: str
    source_port: int
    function_code: int
    function_name: str
    action: str
    reason: str
    unit_id: int = 0
    data_length: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    def to_csv(self) -> str:
        return ",".join(str(v) for v in self.to_dict().values())


class ModbusLogger:
    """Handles all logging for the Modbus Firewall"""
    
    CSV_HEADER = "timestamp,transaction_id,source_ip,source_port,function_code,function_name,action,reason,unit_id,data_length"
    
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG.logging
        self.console = Console()
        
        # Ensure log directory exists
        log_dir = os.path.dirname(self.config.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Initialize log file with header if it doesn't exist
        if not os.path.exists(self.config.log_file):
            with open(self.config.log_file, 'w') as f:
                f.write(self.CSV_HEADER + "\n")
        
        # Initialize alert file
        if not os.path.exists(self.config.alert_file):
            with open(self.config.alert_file, 'w') as f:
                f.write("# Security Alerts Log\n")
        
        # Setup Python logging
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("ModbusFirewall")
    
    def log_transaction(
        self,
        transaction_id: int,
        source_ip: str,
        source_port: int,
        function_code: int,
        action: LogAction,
        reason: str = "",
        unit_id: int = 0,
        data_length: int = 0
    ) -> LogEntry:
        """Log a Modbus transaction"""
        
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            transaction_id=transaction_id,
            source_ip=source_ip,
            source_port=source_port,
            function_code=function_code,
            function_name=get_function_code_name(function_code),
            action=action.value,
            reason=reason,
            unit_id=unit_id,
            data_length=data_length
        )
        
        # Write to log file
        if (action == LogAction.ALLOW and self.config.log_allowed) or \
           (action == LogAction.BLOCK and self.config.log_blocked) or \
           action in (LogAction.ERROR, LogAction.INFO):
            with open(self.config.log_file, 'a') as f:
                f.write(entry.to_csv() + "\n")
        
        # Console output
        if self.config.console_output:
            self._print_transaction(entry)
        
        # Generate alert for blocked write attempts
        if action == LogAction.BLOCK:
            self._generate_alert(entry)
        
        return entry
    
    def _print_transaction(self, entry: LogEntry):
        """Print transaction to console with rich formatting"""
        
        # Color based on action
        if entry.action == "ALLOW":
            color = "green"
            icon = "✓"
        elif entry.action == "BLOCK":
            color = "red"
            icon = "✗"
        elif entry.action == "ERROR":
            color = "yellow"
            icon = "⚠"
        else:
            color = "blue"
            icon = "ℹ"
        
        text = Text()
        text.append(f"[{entry.timestamp}] ", style="dim")
        text.append(f"{icon} ", style=color)
        text.append(f"{entry.action:5} ", style=f"bold {color}")
        text.append(f"TxID:{entry.transaction_id:04X} ", style="cyan")
        text.append(f"FC:{entry.function_code:02X} ({entry.function_name}) ", style="white")
        text.append(f"from {entry.source_ip}:{entry.source_port} ", style="dim")
        if entry.reason:
            text.append(f"| {entry.reason}", style="italic")
        
        self.console.print(text)
    
    def _generate_alert(self, entry: LogEntry):
        """Generate security alert for blocked operations"""
        alert_msg = (
            f"[SECURITY ALERT] {entry.timestamp}\n"
            f"  Blocked {entry.function_name} (FC:{entry.function_code:02X})\n"
            f"  Source: {entry.source_ip}:{entry.source_port}\n"
            f"  Transaction ID: {entry.transaction_id}\n"
            f"  Reason: {entry.reason}\n"
            f"---\n"
        )
        
        with open(self.config.alert_file, 'a') as f:
            f.write(alert_msg)
    
    def log_info(self, message: str):
        """Log informational message"""
        self.logger.info(message)
        if self.config.console_output:
            self.console.print(f"[blue]ℹ[/blue] {message}")
    
    def log_error(self, message: str):
        """Log error message"""
        self.logger.error(message)
        if self.config.console_output:
            self.console.print(f"[red]✗[/red] ERROR: {message}")
    
    def log_warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
        if self.config.console_output:
            self.console.print(f"[yellow]⚠[/yellow] WARNING: {message}")
    
    def print_banner(self):
        """Print startup banner"""
        banner = Panel(
            Text.from_markup(
                "[bold cyan]Modbus Firewall[/bold cyan]\n"
                "[dim]Deep Packet Inspection & Filtering for OT Security[/dim]"
            ),
            border_style="cyan"
        )
        self.console.print(banner)
    
    def print_stats(self, allowed: int, blocked: int, errors: int):
        """Print statistics table"""
        table = Table(title="Firewall Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="right")
        
        table.add_row("Allowed", f"[green]{allowed}[/green]")
        table.add_row("Blocked", f"[red]{blocked}[/red]")
        table.add_row("Errors", f"[yellow]{errors}[/yellow]")
        table.add_row("Total", str(allowed + blocked + errors))
        
        self.console.print(table)


# Global logger instance
_logger: Optional[ModbusLogger] = None


def get_logger() -> ModbusLogger:
    """Get or create the global logger instance"""
    global _logger
    if _logger is None:
        _logger = ModbusLogger()
    return _logger
