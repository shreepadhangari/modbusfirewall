"""
Modbus HTTP Client with Authentication

Wraps Modbus operations in HTTP requests for use with the HTTP Bridge.
Supports session tokens and admin authentication for write access.
"""

import requests
import base64
import struct
from typing import Optional, List
from rich.console import Console

console = Console()


class ModbusHttpClient:
    """
    HTTP-based Modbus client with authentication support.
    Wraps pyModbusTCP-like API but sends requests over HTTP.
    """
    
    def __init__(self, url: str, timeout: float = 10.0):
        """
        Initialize HTTP Modbus client.
        
        Args:
            url: Base URL of the HTTP bridge (e.g., https://xxx.loca.lt)
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.transaction_id = 0
        self.unit_id = 1
        self.last_error = 0
        self.last_error_as_txt = ""
        
        # Authentication
        self.session_token: Optional[str] = None
        self.is_admin = False
        self.access_level = "none"
    
    def create_session(self) -> bool:
        """Create a read-only session"""
        try:
            response = requests.post(
                f"{self.url}/session",
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                self.session_token = data.get('token')
                self.access_level = data.get('access_level', 'readonly')
                self.is_admin = False
                return True
            else:
                self.last_error = response.status_code
                self.last_error_as_txt = "Failed to create session"
                return False
        except Exception as e:
            self.last_error = 4
            self.last_error_as_txt = str(e)
            return False
    
    def authenticate(self, password: str) -> bool:
        """Authenticate as admin with password"""
        try:
            response = requests.post(
                f"{self.url}/auth",
                json={"password": password},
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                self.session_token = data.get('token')
                self.access_level = data.get('access_level', 'admin')
                self.is_admin = True
                return True
            elif response.status_code == 401:
                self.last_error = 401
                self.last_error_as_txt = "Invalid password"
                return False
            else:
                self.last_error = response.status_code
                self.last_error_as_txt = "Authentication failed"
                return False
        except Exception as e:
            self.last_error = 4
            self.last_error_as_txt = str(e)
            return False
    
    def _next_transaction_id(self) -> int:
        """Get next transaction ID"""
        self.transaction_id = (self.transaction_id + 1) % 65536
        return self.transaction_id
    
    def _build_request_frame(self, function_code: int, data: bytes) -> bytes:
        """Build a Modbus TCP frame"""
        tx_id = self._next_transaction_id()
        protocol_id = 0
        length = 2 + len(data)  # Unit ID + Function Code + Data
        
        header = struct.pack('>HHHBB', tx_id, protocol_id, length, self.unit_id, function_code)
        return header + data
    
    def _send_request(self, frame: bytes) -> Optional[bytes]:
        """Send Modbus frame via HTTP and return response"""
        try:
            # Encode frame as base64
            payload = {"data": base64.b64encode(frame).decode('ascii')}
            
            # Add session token header
            headers = {"Content-Type": "application/json"}
            if self.session_token:
                headers["X-Session-Token"] = self.session_token
            
            # Send to bridge
            response = requests.post(
                f"{self.url}/modbus",
                json=payload,
                timeout=self.timeout,
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    return base64.b64decode(data['data'])
                else:
                    self.last_error = 1
                    self.last_error_as_txt = data.get('error', 'Unknown error')
                    return None
            elif response.status_code == 401:
                self.last_error = 401
                data = response.json()
                self.last_error_as_txt = data.get('error', 'Session required')
                return None
            elif response.status_code == 403:
                self.last_error = 403
                data = response.json()
                self.last_error_as_txt = data.get('error', 'Admin access required')
                return None
            else:
                self.last_error = response.status_code
                self.last_error_as_txt = f"HTTP {response.status_code}"
                return None
                
        except requests.exceptions.Timeout:
            self.last_error = 2
            self.last_error_as_txt = "Timeout"
            return None
        except requests.exceptions.ConnectionError:
            self.last_error = 3
            self.last_error_as_txt = "Connection failed"
            return None
        except Exception as e:
            self.last_error = 4
            self.last_error_as_txt = str(e)
            return None
    
    def _parse_read_response(self, response: bytes, expected_fc: int) -> Optional[List[int]]:
        """Parse a Modbus read response"""
        if not response or len(response) < 9:
            return None
        
        fc = response[7]
        
        # Check for exception
        if fc >= 0x80:
            self.last_error = 7
            self.last_error_as_txt = "modbus exception"
            return None
        
        if fc != expected_fc:
            self.last_error = 5
            self.last_error_as_txt = f"Unexpected FC: {fc}"
            return None
        
        byte_count = response[8]
        data = response[9:9+byte_count]
        
        if expected_fc in [1, 2]:  # Coils or Discrete Inputs
            result = []
            for byte in data:
                for bit in range(8):
                    result.append(bool(byte & (1 << bit)))
            return result
        else:  # Registers
            result = []
            for i in range(0, len(data), 2):
                if i + 1 < len(data):
                    result.append(struct.unpack('>H', data[i:i+2])[0])
            return result
    
    def open(self) -> bool:
        """Test connection to HTTP bridge"""
        try:
            response = requests.get(f"{self.url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def close(self) -> None:
        """Clear session"""
        self.session_token = None
        self.is_admin = False
        self.access_level = "none"
    
    def read_coils(self, address: int, count: int) -> Optional[List[bool]]:
        """Read coils (FC 01)"""
        data = struct.pack('>HH', address, count)
        frame = self._build_request_frame(1, data)
        response = self._send_request(frame)
        result = self._parse_read_response(response, 1)
        return result[:count] if result else None
    
    def read_discrete_inputs(self, address: int, count: int) -> Optional[List[bool]]:
        """Read discrete inputs (FC 02)"""
        data = struct.pack('>HH', address, count)
        frame = self._build_request_frame(2, data)
        response = self._send_request(frame)
        result = self._parse_read_response(response, 2)
        return result[:count] if result else None
    
    def read_holding_registers(self, address: int, count: int) -> Optional[List[int]]:
        """Read holding registers (FC 03)"""
        data = struct.pack('>HH', address, count)
        frame = self._build_request_frame(3, data)
        response = self._send_request(frame)
        return self._parse_read_response(response, 3)
    
    def read_input_registers(self, address: int, count: int) -> Optional[List[int]]:
        """Read input registers (FC 04)"""
        data = struct.pack('>HH', address, count)
        frame = self._build_request_frame(4, data)
        response = self._send_request(frame)
        return self._parse_read_response(response, 4)
    
    def write_single_coil(self, address: int, value: bool) -> bool:
        """Write single coil (FC 05)"""
        coil_value = 0xFF00 if value else 0x0000
        data = struct.pack('>HH', address, coil_value)
        frame = self._build_request_frame(5, data)
        response = self._send_request(frame)
        
        if response and len(response) >= 8:
            fc = response[7]
            return fc == 5
        return False
    
    def write_single_register(self, address: int, value: int) -> bool:
        """Write single register (FC 06)"""
        data = struct.pack('>HH', address, value)
        frame = self._build_request_frame(6, data)
        response = self._send_request(frame)
        
        if response and len(response) >= 8:
            fc = response[7]
            return fc == 6
        return False
    
    def write_multiple_coils(self, address: int, values: List[bool]) -> bool:
        """Write multiple coils (FC 15)"""
        count = len(values)
        byte_count = (count + 7) // 8
        
        # Pack bits into bytes
        coil_bytes = bytearray(byte_count)
        for i, val in enumerate(values):
            if val:
                coil_bytes[i // 8] |= (1 << (i % 8))
        
        data = struct.pack('>HHB', address, count, byte_count) + bytes(coil_bytes)
        frame = self._build_request_frame(15, data)
        response = self._send_request(frame)
        
        if response and len(response) >= 8:
            fc = response[7]
            return fc == 15
        return False
    
    def write_multiple_registers(self, address: int, values: List[int]) -> bool:
        """Write multiple registers (FC 16)"""
        count = len(values)
        byte_count = count * 2
        
        data = struct.pack('>HHB', address, count, byte_count)
        for v in values:
            data += struct.pack('>H', v)
        
        frame = self._build_request_frame(16, data)
        response = self._send_request(frame)
        
        if response and len(response) >= 8:
            fc = response[7]
            return fc == 16
        return False


# Test the HTTP client
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test HTTP Modbus Client")
    parser.add_argument("url", help="HTTP Bridge URL (e.g., https://xxx.loca.lt)")
    parser.add_argument("--password", "-p", help="Admin password for write access")
    args = parser.parse_args()
    
    client = ModbusHttpClient(args.url)
    
    if client.open():
        console.print("[green]✓[/green] Connected to HTTP Bridge")
        
        # Authenticate or create read-only session
        if args.password:
            if client.authenticate(args.password):
                console.print(f"[green]✓[/green] Authenticated as ADMIN")
            else:
                console.print(f"[red]✗[/red] Auth failed: {client.last_error_as_txt}")
                client.create_session()
        else:
            client.create_session()
            console.print(f"[yellow]ℹ[/yellow] Read-only session (use -p for admin)")
        
        # Test read
        coils = client.read_coils(0, 8)
        if coils:
            console.print(f"Coils: {coils}")
        else:
            console.print(f"[red]Read failed: {client.last_error_as_txt}[/red]")
    else:
        console.print("[red]✗[/red] Failed to connect")
