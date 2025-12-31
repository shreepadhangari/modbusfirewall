"""
Modbus Firewall - Configuration Module

Centralized configuration for all components of the Modbus Firewall system.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set
from enum import IntEnum


class ModbusFunctionCode(IntEnum):
    """Modbus Function Codes"""
    # Read Operations (Typically Safe)
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    
    # Write Operations (Potentially Dangerous)
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F  # 15
    WRITE_MULTIPLE_REGISTERS = 0x10  # 16
    READ_WRITE_MULTIPLE_REGISTERS = 0x17  # 23
    
    # Diagnostics
    READ_EXCEPTION_STATUS = 0x07
    DIAGNOSTICS = 0x08
    GET_COMM_EVENT_COUNTER = 0x0B
    GET_COMM_EVENT_LOG = 0x0C
    REPORT_SERVER_ID = 0x11
    READ_DEVICE_IDENTIFICATION = 0x2B


@dataclass
class NetworkConfig:
    """Network configuration settings"""
    # Firewall listens on this address/port (client-facing)
    firewall_host: str = "0.0.0.0"
    firewall_port: int = 502
    
    # PLC server address (downstream)
    plc_host: str = "127.0.0.1"
    plc_port: int = 5020
    
    # Connection settings
    connection_timeout: float = 10.0
    max_connections: int = 10


@dataclass
class LocalSecurityPolicy:
    """Security policy for LOCAL connections (no authentication required)"""
    
    # Function codes allowed for local connections
    allowed_function_codes: Set[int] = field(default_factory=lambda: {
        # Read operations
        ModbusFunctionCode.READ_COILS,
        ModbusFunctionCode.READ_DISCRETE_INPUTS,
        ModbusFunctionCode.READ_HOLDING_REGISTERS,
        ModbusFunctionCode.READ_INPUT_REGISTERS,
        # Write operations (full access for local)
        ModbusFunctionCode.WRITE_SINGLE_REGISTER,
        ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
    })
    
    # Function codes explicitly blocked
    blocked_function_codes: Set[int] = field(default_factory=lambda: {
        ModbusFunctionCode.WRITE_SINGLE_COIL,
        ModbusFunctionCode.WRITE_MULTIPLE_COILS,
        ModbusFunctionCode.READ_WRITE_MULTIPLE_REGISTERS,
    })


@dataclass
class RemoteSecurityPolicy:
    """Security policy for REMOTE connections (authentication required for writes)"""
    
    # Read-only function codes (for non-admin remote users)
    readonly_function_codes: Set[int] = field(default_factory=lambda: {
        ModbusFunctionCode.READ_COILS,
        ModbusFunctionCode.READ_DISCRETE_INPUTS,
        ModbusFunctionCode.READ_HOLDING_REGISTERS,
        ModbusFunctionCode.READ_INPUT_REGISTERS,
    })
    
    # Admin function codes (for authenticated admin remote users)
    admin_function_codes: Set[int] = field(default_factory=lambda: {
        # Read operations
        ModbusFunctionCode.READ_COILS,
        ModbusFunctionCode.READ_DISCRETE_INPUTS,
        ModbusFunctionCode.READ_HOLDING_REGISTERS,
        ModbusFunctionCode.READ_INPUT_REGISTERS,
        # Write operations (admin only)
        ModbusFunctionCode.WRITE_SINGLE_REGISTER,
        ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
    })
    
    # Function codes always blocked for remote
    blocked_function_codes: Set[int] = field(default_factory=lambda: {
        # Coil writes blocked even for admin (safety critical)
        ModbusFunctionCode.WRITE_SINGLE_COIL,
        ModbusFunctionCode.WRITE_MULTIPLE_COILS,
        ModbusFunctionCode.READ_WRITE_MULTIPLE_REGISTERS,
    })


@dataclass
class AuthConfig:
    """Authentication configuration for remote access"""
    admin_password_length: int = 8
    max_login_attempts: int = 3
    session_timeout_minutes: int = 30


# Keep legacy SecurityPolicy for backward compatibility
@dataclass
class SecurityPolicy:
    """Legacy security policy (use LocalSecurityPolicy/RemoteSecurityPolicy instead)"""
    allowed_function_codes: Set[int] = field(default_factory=lambda: {
        ModbusFunctionCode.READ_COILS,
        ModbusFunctionCode.READ_DISCRETE_INPUTS,
        ModbusFunctionCode.READ_HOLDING_REGISTERS,
        ModbusFunctionCode.READ_INPUT_REGISTERS,
        ModbusFunctionCode.WRITE_SINGLE_REGISTER,
        ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
    })
    blocked_function_codes: Set[int] = field(default_factory=lambda: {
        ModbusFunctionCode.WRITE_SINGLE_COIL,
        ModbusFunctionCode.WRITE_MULTIPLE_COILS,
        ModbusFunctionCode.READ_WRITE_MULTIPLE_REGISTERS,
    })
    write_allowed_ips: Set[str] = field(default_factory=set)
    maintenance_mode: bool = False
    rate_limit: int = 100
    register_policies: Dict[int, Set[int]] = field(default_factory=dict)


@dataclass
class LoggingConfig:
    """Logging configuration"""
    log_file: str = "modbus_firewall.log"
    alert_file: str = "security_alerts.log"
    log_level: str = "INFO"
    console_output: bool = True
    log_allowed: bool = True
    log_blocked: bool = True


@dataclass
class PLCConfig:
    """Simulated PLC configuration"""
    host: str = "127.0.0.1"
    port: int = 5020
    
    # Register counts
    num_coils: int = 100
    num_discrete_inputs: int = 100
    num_input_registers: int = 100
    num_holding_registers: int = 100
    
    # Simulation settings
    update_interval: float = 1.0  # seconds


@dataclass
class Config:
    """Main configuration container"""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security: SecurityPolicy = field(default_factory=SecurityPolicy)  # Legacy
    local_security: LocalSecurityPolicy = field(default_factory=LocalSecurityPolicy)
    remote_security: RemoteSecurityPolicy = field(default_factory=RemoteSecurityPolicy)
    auth: AuthConfig = field(default_factory=AuthConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    plc: PLCConfig = field(default_factory=PLCConfig)


# Default configuration instance
DEFAULT_CONFIG = Config()


def get_function_code_name(fc: int) -> str:
    """Get human-readable name for a function code"""
    try:
        return ModbusFunctionCode(fc).name
    except ValueError:
        return f"UNKNOWN_FC_{fc}"
