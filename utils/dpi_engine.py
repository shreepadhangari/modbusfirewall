"""
Modbus Firewall - Deep Packet Inspection Engine

Parses and validates Modbus TCP ADU (Application Data Unit) structure.
"""

from dataclasses import dataclass
from typing import Optional, Tuple
from enum import IntEnum

from core.config import ModbusFunctionCode


class ModbusException(IntEnum):
    """Modbus Exception Codes"""
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SERVER_DEVICE_FAILURE = 0x04
    ACKNOWLEDGE = 0x05
    SERVER_DEVICE_BUSY = 0x06
    MEMORY_PARITY_ERROR = 0x08
    GATEWAY_PATH_UNAVAILABLE = 0x0A
    GATEWAY_TARGET_FAILED = 0x0B


@dataclass
class ModbusTCPFrame:
    """Represents a parsed Modbus TCP frame"""
    # MBAP Header (Modbus Application Protocol Header)
    transaction_id: int      # Bytes 0-1: Transaction identifier
    protocol_id: int         # Bytes 2-3: Protocol identifier (0x0000 for Modbus)
    length: int              # Bytes 4-5: Length of remaining bytes
    unit_id: int             # Byte 6: Unit identifier (slave address)
    
    # PDU (Protocol Data Unit)
    function_code: int       # Byte 7: Function code
    data: bytes              # Remaining bytes: Request/Response data
    
    # Raw frame for forwarding
    raw: bytes = b''
    
    @property
    def is_exception(self) -> bool:
        """Check if this is an exception response"""
        return self.function_code >= 0x80
    
    @property
    def original_function_code(self) -> int:
        """Get original function code (strips exception bit)"""
        if self.is_exception:
            return self.function_code - 0x80
        return self.function_code
    
    @property
    def is_write_operation(self) -> bool:
        """Check if this is a write operation"""
        return self.function_code in {
            ModbusFunctionCode.WRITE_SINGLE_COIL,
            ModbusFunctionCode.WRITE_SINGLE_REGISTER,
            ModbusFunctionCode.WRITE_MULTIPLE_COILS,
            ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
            ModbusFunctionCode.READ_WRITE_MULTIPLE_REGISTERS,
        }
    
    @property
    def is_read_operation(self) -> bool:
        """Check if this is a read operation"""
        return self.function_code in {
            ModbusFunctionCode.READ_COILS,
            ModbusFunctionCode.READ_DISCRETE_INPUTS,
            ModbusFunctionCode.READ_HOLDING_REGISTERS,
            ModbusFunctionCode.READ_INPUT_REGISTERS,
        }


class DPIEngine:
    """Deep Packet Inspection Engine for Modbus TCP"""
    
    MODBUS_PROTOCOL_ID = 0x0000
    MIN_FRAME_LENGTH = 8  # Minimum valid Modbus TCP frame
    MAX_FRAME_LENGTH = 260  # Maximum ADU size
    
    def __init__(self):
        self.stats = {
            'parsed': 0,
            'invalid_protocol': 0,
            'invalid_length': 0,
            'malformed': 0,
        }
    
    def parse_frame(self, data: bytes) -> Tuple[Optional[ModbusTCPFrame], Optional[str]]:
        """
        Parse a Modbus TCP frame.
        
        Returns:
            Tuple of (ModbusTCPFrame or None, error_message or None)
        """
        if len(data) < self.MIN_FRAME_LENGTH:
            self.stats['malformed'] += 1
            return None, f"Frame too short: {len(data)} bytes (minimum: {self.MIN_FRAME_LENGTH})"
        
        if len(data) > self.MAX_FRAME_LENGTH:
            self.stats['malformed'] += 1
            return None, f"Frame too long: {len(data)} bytes (maximum: {self.MAX_FRAME_LENGTH})"
        
        try:
            # Parse MBAP Header
            transaction_id = int.from_bytes(data[0:2], 'big')
            protocol_id = int.from_bytes(data[2:4], 'big')
            length = int.from_bytes(data[4:6], 'big')
            unit_id = data[6]
            function_code = data[7]
            
            # Validate protocol ID
            if protocol_id != self.MODBUS_PROTOCOL_ID:
                self.stats['invalid_protocol'] += 1
                return None, f"Invalid protocol ID: 0x{protocol_id:04X} (expected: 0x0000)"
            
            # Validate length field consistency
            expected_length = len(data) - 6  # Length field excludes first 6 bytes
            if length != expected_length:
                self.stats['invalid_length'] += 1
                return None, f"Length mismatch: header says {length}, actual is {expected_length}"
            
            # Validate unit ID range (typically 1-247 for slaves, 0 and 255 reserved)
            if unit_id > 247 and unit_id != 255:
                return None, f"Invalid unit ID: {unit_id}"
            
            # Extract PDU data
            pdu_data = data[8:] if len(data) > 8 else b''
            
            frame = ModbusTCPFrame(
                transaction_id=transaction_id,
                protocol_id=protocol_id,
                length=length,
                unit_id=unit_id,
                function_code=function_code,
                data=pdu_data,
                raw=data
            )
            
            self.stats['parsed'] += 1
            return frame, None
            
        except Exception as e:
            self.stats['malformed'] += 1
            return None, f"Parse error: {str(e)}"
    
    def create_exception_response(
        self,
        original_frame: ModbusTCPFrame,
        exception_code: ModbusException = ModbusException.ILLEGAL_FUNCTION
    ) -> bytes:
        """
        Create a Modbus exception response frame.
        
        Args:
            original_frame: The original request frame
            exception_code: The exception code to return
            
        Returns:
            bytes: The exception response frame
        """
        # Exception Function Code = Original FC + 0x80
        exception_fc = original_frame.function_code + 0x80
        
        # Build response frame
        response = bytearray()
        
        # MBAP Header
        response.extend(original_frame.transaction_id.to_bytes(2, 'big'))  # Transaction ID
        response.extend((0x0000).to_bytes(2, 'big'))  # Protocol ID
        response.extend((3).to_bytes(2, 'big'))  # Length (Unit ID + FC + Exception Code)
        response.append(original_frame.unit_id)  # Unit ID
        
        # PDU
        response.append(exception_fc)  # Exception Function Code
        response.append(exception_code)  # Exception Code
        
        return bytes(response)
    
    def validate_frame_integrity(self, frame: ModbusTCPFrame) -> Tuple[bool, Optional[str]]:
        """
        Perform additional integrity checks on a parsed frame.
        
        Returns:
            Tuple of (is_valid, error_message or None)
        """
        # Check for valid function code range
        if frame.function_code == 0:
            return False, "Function code 0 is invalid"
        
        # Validate data length for specific function codes
        fc = frame.function_code
        data_len = len(frame.data)
        
        if fc == ModbusFunctionCode.READ_COILS or fc == ModbusFunctionCode.READ_DISCRETE_INPUTS:
            if data_len != 4:
                return False, f"Invalid data length for FC {fc}: expected 4, got {data_len}"
        
        elif fc == ModbusFunctionCode.READ_HOLDING_REGISTERS or fc == ModbusFunctionCode.READ_INPUT_REGISTERS:
            if data_len != 4:
                return False, f"Invalid data length for FC {fc}: expected 4, got {data_len}"
        
        elif fc == ModbusFunctionCode.WRITE_SINGLE_COIL or fc == ModbusFunctionCode.WRITE_SINGLE_REGISTER:
            if data_len != 4:
                return False, f"Invalid data length for FC {fc}: expected 4, got {data_len}"
        
        elif fc == ModbusFunctionCode.WRITE_MULTIPLE_COILS or fc == ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS:
            if data_len < 5:
                return False, f"Invalid data length for FC {fc}: expected at least 5, got {data_len}"
        
        return True, None
    
    def get_register_address(self, frame: ModbusTCPFrame) -> Optional[int]:
        """Extract the starting register address from a frame"""
        if len(frame.data) >= 2:
            return int.from_bytes(frame.data[0:2], 'big')
        return None
    
    def get_register_count(self, frame: ModbusTCPFrame) -> Optional[int]:
        """Extract the register count from a read/write multiple request"""
        if len(frame.data) >= 4:
            return int.from_bytes(frame.data[2:4], 'big')
        return None
    
    def get_stats(self) -> dict:
        """Get parsing statistics"""
        return self.stats.copy()
