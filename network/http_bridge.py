"""
Modbus HTTP Bridge with Authentication

HTTP server that bridges Modbus TCP traffic over HTTP for use with LocalTunnel.
Includes role-based access control with session tokens for remote admin access.
"""

import asyncio
import base64
import secrets
import hashlib
import hmac
import time
from aiohttp import web
from typing import Optional, Dict
from rich.console import Console
from core.config import DEFAULT_CONFIG

console = Console()

# Session token expiry (in seconds)
SESSION_EXPIRY = 30 * 60  # 30 minutes


class ModbusHttpBridge:
    """HTTP bridge with authentication for Modbus over HTTP"""
    
    def __init__(self, modbus_host: str = "127.0.0.1", modbus_port: int = 502, http_port: int = 8080):
        self.modbus_host = modbus_host
        self.modbus_port = modbus_port
        self.http_port = http_port
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        
        # Authentication
        self.admin_password: Optional[str] = None
        self.sessions: Dict[str, Dict] = {}  # token -> {created_at, is_admin}
        self.secret_key = secrets.token_bytes(32)  # For signing tokens
        
        self.setup_routes()
    
    def generate_admin_password(self) -> str:
        """Generate a random admin password"""
        length = DEFAULT_CONFIG.auth.admin_password_length
        # Generate alphanumeric password
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
        self.admin_password = ''.join(secrets.choice(chars) for _ in range(length))
        return self.admin_password
    
    def create_session(self, is_admin: bool = False) -> str:
        """Create a new session token"""
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {
            'created_at': time.time(),
            'is_admin': is_admin
        }
        return token
    
    def validate_session(self, token: str) -> Dict:
        """Validate session token and return session info"""
        if not token or token not in self.sessions:
            return {'valid': False, 'is_admin': False}
        
        session = self.sessions[token]
        age = time.time() - session['created_at']
        
        if age > SESSION_EXPIRY:
            del self.sessions[token]
            return {'valid': False, 'is_admin': False, 'expired': True}
        
        return {'valid': True, 'is_admin': session['is_admin']}
    
    def is_write_operation(self, modbus_frame: bytes) -> bool:
        """Check if the Modbus frame is a write operation"""
        if len(modbus_frame) < 8:
            return False
        function_code = modbus_frame[7]
        write_codes = {0x05, 0x06, 0x0F, 0x10, 0x17}  # FC 5,6,15,16,23
        return function_code in write_codes
    
    def setup_routes(self):
        """Setup HTTP routes"""
        self.app.router.add_post('/modbus', self.handle_modbus_request)
        self.app.router.add_post('/auth', self.handle_auth)
        self.app.router.add_post('/session', self.handle_create_session)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/', self.handle_index)
    
    async def handle_index(self, request: web.Request) -> web.Response:
        """Index page with usage info"""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Modbus HTTP Bridge</title></head>
        <body style="font-family: Arial; padding: 20px; background: #1a1a2e; color: #eee;">
            <h1>🔌 Modbus HTTP Bridge</h1>
            <p>Secure bridge for Modbus TCP over HTTP with role-based access.</p>
            <h2>🔐 Access Levels:</h2>
            <ul>
                <li><strong>Read-Only</strong>: No authentication required</li>
                <li><strong>Admin</strong>: Password required for write operations</li>
            </ul>
            <h2>API Endpoints:</h2>
            <ul>
                <li><code>POST /session</code> - Create read-only session</li>
                <li><code>POST /auth</code> - Authenticate as admin</li>
                <li><code>POST /modbus</code> - Send Modbus frame</li>
                <li><code>GET /health</code> - Health check</li>
            </ul>
            <p style="color: #0f0;">✓ Bridge is running</p>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "ok",
            "modbus_target": f"{self.modbus_host}:{self.modbus_port}",
            "auth_required": True
        })
    
    async def handle_create_session(self, request: web.Request) -> web.Response:
        """Create a read-only session token"""
        token = self.create_session(is_admin=False)
        return web.json_response({
            "token": token,
            "access_level": "readonly",
            "expires_in": SESSION_EXPIRY
        })
    
    async def handle_auth(self, request: web.Request) -> web.Response:
        """Authenticate as admin with password"""
        try:
            data = await request.json()
            password = data.get('password', '')
            
            if not self.admin_password:
                return web.json_response({
                    "error": "Admin access not configured"
                }, status=503)
            
            if password == self.admin_password:
                token = self.create_session(is_admin=True)
                return web.json_response({
                    "token": token,
                    "access_level": "admin",
                    "expires_in": SESSION_EXPIRY
                })
            else:
                return web.json_response({
                    "error": "Invalid password"
                }, status=401)
                
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)
    
    async def handle_modbus_request(self, request: web.Request) -> web.Response:
        """Handle Modbus request with access control"""
        try:
            # Get client IP address (check forwarded headers for proxy/tunnel)
            client_ip = request.headers.get('X-Forwarded-For', 
                        request.headers.get('X-Real-IP',
                        request.remote or 'unknown'))
            # If X-Forwarded-For has multiple IPs, take the first one
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Get session token from header
            token = request.headers.get('X-Session-Token', '')
            session = self.validate_session(token)
            access_level = "ADMIN" if session.get('is_admin') else "READ-ONLY"
            
            # Parse request
            data = await request.json()
            
            if 'data' not in data:
                return web.json_response({"error": "Missing 'data' field"}, status=400)
            
            # Decode base64 Modbus frame
            try:
                modbus_frame = base64.b64decode(data['data'])
            except Exception as e:
                return web.json_response({"error": f"Invalid base64: {e}"}, status=400)
            
            # Extract function code for logging
            fc = modbus_frame[7] if len(modbus_frame) > 7 else 0
            
            # Access control check
            is_write = self.is_write_operation(modbus_frame)
            
            if is_write:
                if not session['valid']:
                    console.print(f"[yellow]HTTPS[/yellow] {client_ip} | FC 0x{fc:02X} | [red]BLOCKED[/red] (no session)")
                    return web.json_response({
                        "error": "Session required for write operations",
                        "code": "NO_SESSION"
                    }, status=401)
                
                if not session['is_admin']:
                    console.print(f"[yellow]HTTPS[/yellow] {client_ip} | FC 0x{fc:02X} | [red]BLOCKED[/red] (read-only)")
                    return web.json_response({
                        "error": "Admin access required for write operations",
                        "code": "READ_ONLY"
                    }, status=403)
            
            # Log the request
            action_color = "green" if not is_write else "cyan"
            console.print(f"[yellow]HTTPS[/yellow] {client_ip} | FC 0x{fc:02X} | [{action_color}]ALLOWED[/{action_color}] ({access_level})")
            
            # Forward to Modbus server
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.modbus_host, self.modbus_port),
                    timeout=5.0
                )
                
                writer.write(modbus_frame)
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(260), timeout=5.0)
                
                writer.close()
                await writer.wait_closed()
                
                return web.json_response({
                    "data": base64.b64encode(response).decode('ascii'),
                    "length": len(response),
                    "access_level": "admin" if session.get('is_admin') else "readonly"
                })
                
            except asyncio.TimeoutError:
                return web.json_response({"error": "Modbus timeout"}, status=504)
            except ConnectionRefusedError:
                return web.json_response({"error": "Modbus connection refused"}, status=502)
            except Exception as e:
                return web.json_response({"error": f"Modbus error: {e}"}, status=502)
                
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def start(self):
        """Start the HTTP bridge server"""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, '0.0.0.0', self.http_port)
        await site.start()
        console.print(f"[green]✓[/green] HTTP Bridge listening on 0.0.0.0:{self.http_port}")
    
    async def stop(self):
        """Stop the HTTP bridge server"""
        if self.runner:
            await self.runner.cleanup()


async def main():
    """Standalone HTTP bridge for testing"""
    bridge = ModbusHttpBridge(modbus_host="127.0.0.1", modbus_port=502, http_port=8080)
    bridge.generate_admin_password()
    console.print(f"[bold yellow]Admin Password: {bridge.admin_password}[/bold yellow]")
    
    await bridge.start()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await bridge.stop()


if __name__ == "__main__":
    asyncio.run(main())
