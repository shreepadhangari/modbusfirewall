"""
Modbus Firewall - HMI Client

Interactive Modbus client for testing the firewall.
"""

import sys
import time
from pyModbusTCP.client import ModbusClient
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm

from core.config import DEFAULT_CONFIG, ModbusFunctionCode


class ModbusHMI:
    """Interactive HMI Client for Modbus operations"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 502):
        self.console = Console()
        self.host = host
        self.port = port
        self.client = None
        
        # Connection state (set by main())
        self.is_remote = False
        self.is_admin = True
        self.access_level = "LOCAL"
        
        # Security policies from config
        self.local_policy = DEFAULT_CONFIG.local_security
        self.remote_policy = DEFAULT_CONFIG.remote_security
    
    def get_active_policy_allowed(self) -> set:
        """Get the allowed function codes based on current connection mode"""
        if not self.is_remote:
            # Local connection - use local policy
            return self.local_policy.allowed_function_codes
        else:
            # Remote connection
            if self.is_admin:
                return self.remote_policy.admin_function_codes
            else:
                return self.remote_policy.readonly_function_codes
    
    def get_active_policy_blocked(self) -> set:
        """Get the blocked function codes based on current connection mode"""
        if not self.is_remote:
            return self.local_policy.blocked_function_codes
        else:
            return self.remote_policy.blocked_function_codes
    
    def get_operation_status(self, function_code: int) -> str:
        """Get the allowed/blocked status for a function code based on active policy"""
        allowed = self.get_active_policy_allowed()
        blocked = self.get_active_policy_blocked()
        
        if function_code in blocked:
            return "[red]✗ Blocked[/red]"
        elif function_code in allowed:
            return "[green]✓ Allowed[/green]"
        else:
            return "[yellow]? Unknown[/yellow]"
    
    def is_operation_allowed(self, function_code: int) -> bool:
        """Check if a function code is allowed by active security policy"""
        allowed = self.get_active_policy_allowed()
        blocked = self.get_active_policy_blocked()
        return function_code in allowed and function_code not in blocked
        
    def connect(self) -> bool:
        """Connect to the Modbus server (through firewall)"""
        self.client = ModbusClient(host=self.host, port=self.port, auto_open=True)
        self.client.timeout = 5.0
        
        if self.client.open():
            self.console.print(f"[green]✓[/green] Connected to {self.host}:{self.port}")
            return True
        else:
            self.console.print(f"[red]✗[/red] Failed to connect to {self.host}:{self.port}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.client:
            self.client.close()
            self.console.print("[yellow]Disconnected[/yellow]")
    
    def read_coils(self, start_addr: int = 0, count: int = 10):
        """Read coils (FC 01)"""
        # Coil names (Thermal Power Plant)
        coil_names = {
            0: "Fuel_Motor",
            1: "Feedwater_Pump",
            2: "Steam_Valve",
            3: "Air_Fan",
            4: "Turbine_Enable",
            5: "Generator_Connect",
            6: "Plant_Run",
            7: "Alarm_Enable",
        }
        
        self.console.print(f"\n[cyan]Reading {count} coils from address {start_addr}...[/cyan]")
        
        result = self.client.read_coils(start_addr, count)
        
        if result is not None:
            table = Table(title="Coils (FC 01)")
            table.add_column("Address", justify="right")
            table.add_column("Name", width=16)
            table.add_column("Status")
            
            for i, val in enumerate(result):
                addr = start_addr + i
                name = coil_names.get(addr, f"Coil_{addr}")
                status = "[green]ON[/green]" if val else "[red]OFF[/red]"
                table.add_row(str(addr), name, status)
            
            self.console.print(table)
        else:
            self.console.print("[red]✗[/red] Read failed (possibly blocked by firewall)")
    
    def read_discrete_inputs(self, start_addr: int = 0, count: int = 10):
        """Read discrete inputs (FC 02)"""
        # Discrete input names (Thermal Power Plant)
        discrete_names = {
            0: "Boiler_Lvl_Hi",
            1: "Boiler_Lvl_Lo",
            2: "Boiler_Press_Hi",
            3: "Boiler_Press_Lo",
            4: "Boiler_Temp_Hi",
            5: "Turbine_Trip",
            6: "E-Stop_OK",
            7: "Fault_Active",
        }
        
        self.console.print(f"\n[cyan]Reading {count} discrete inputs from address {start_addr}...[/cyan]")
        
        result = self.client.read_discrete_inputs(start_addr, count)
        
        if result is not None:
            table = Table(title="Discrete Inputs (FC 02)")
            table.add_column("Address", justify="right")
            table.add_column("Name", width=16)
            table.add_column("Status")
            
            for i, val in enumerate(result):
                addr = start_addr + i
                name = discrete_names.get(addr, f"DI_{addr}")
                status = "[green]ON[/green]" if val else "[red]OFF[/red]"
                table.add_row(str(addr), name, status)
            
            self.console.print(table)
        else:
            self.console.print("[red]✗[/red] Read failed (possibly blocked by firewall)")
    
    def read_holding_registers(self, start_addr: int = 0, count: int = 10):
        """Read holding registers (FC 03)"""
        self.console.print(f"\n[cyan]Reading {count} holding registers from address {start_addr}...[/cyan]")
        
        result = self.client.read_holding_registers(start_addr, count)
        
        if result is not None:
            table = Table(title="Holding Registers (FC 03)")
            table.add_column("Address", justify="right")
            table.add_column("Name", width=12)
            table.add_column("Raw", justify="right")
            table.add_column("Scaled", justify="right")
            
            # Same scaling as server (Power Plant Theme)
            reg_info = {
                0: ("Boiler_Temp_SP", "°C", 1),
                1: ("Boiler_Press_SP", "bar", 1),
                2: ("Steam_Temp_SP", "°C", 1),
                3: ("Steam_Press_SP", "bar", 1),
                4: ("Turbine_Spd_SP", "RPM", 1),
                5: ("Gen_Load_SP", "%", 1),
                6: ("FW_Temp_SP", "°C", 10),
                7: ("FW_Press_SP", "bar", 10),
                8: ("Plant_Mode", "", 1),
            }
            
            for i, val in enumerate(result):
                addr = start_addr + i
                if addr in reg_info:
                    name, unit, scale = reg_info[addr]
                    if addr == 8:
                        scaled = "Auto" if val == 0 else "Manual"
                    elif unit:
                        scaled = f"{val/scale:.1f} {unit}"
                    else:
                        scaled = str(val)
                else:
                    name = f"HR {addr}"
                    scaled = str(val)
                table.add_row(str(addr), name, str(val), scaled)
            
            self.console.print(table)
        else:
            self.console.print("[red]✗[/red] Read failed (possibly blocked by firewall)")
    
    def read_input_registers(self, start_addr: int = 0, count: int = 10):
        """Read input registers (FC 04)"""
        self.console.print(f"\n[cyan]Reading {count} input registers from address {start_addr}...[/cyan]")
        
        result = self.client.read_input_registers(start_addr, count)
        
        if result is not None:
            table = Table(title="Input Registers (FC 04)")
            table.add_column("Address", justify="right")
            table.add_column("Name", width=12)
            table.add_column("Raw", justify="right")
            table.add_column("Scaled", justify="right")
            
            # Same scaling as server (Power Plant Theme)
            reg_info = {
                0: ("Feedwater_Temp", "°C", 10),
                1: ("Feedwater_Press", "bar", 10),
                2: ("Boiler_Temp", "°C", 1),
                3: ("Boiler_Press", "bar", 1),
                4: ("Steam_Temp", "°C", 1),
                5: ("Steam_Press", "bar", 1),
                6: ("Turbine_Speed", "RPM", 1),
                7: ("Gen_Frequency", "Hz", 10),
            }
            
            for i, val in enumerate(result):
                addr = start_addr + i
                if addr in reg_info:
                    name, unit, scale = reg_info[addr]
                    scaled = f"{val/scale:.1f} {unit}"
                else:
                    name = f"IR {addr}"
                    scaled = str(val)
                table.add_row(str(addr), name, str(val), scaled)
            
            self.console.print(table)
        else:
            self.console.print("[red]✗[/red] Read failed (possibly blocked by firewall)")
    
    def write_single_coil(self, address: int, value: bool):
        """Write single coil (FC 05)"""
        self.console.print(f"\n[yellow]⚠ Attempting to write coil {address} = {value}...[/yellow]")
        
        is_allowed = self.is_operation_allowed(ModbusFunctionCode.WRITE_SINGLE_COIL)
        if not is_allowed:
            self.console.print("[dim]This operation is blocked by security policy[/dim]")
        
        result = self.client.write_single_coil(address, value)
        
        if result:
            self.console.print(f"[green]✓[/green] Write succeeded! Coil {address} set to {value}")
        else:
            # Debug: show actual error
            last_error = self.client.last_error
            last_error_txt = self.client.last_error_as_txt
            self.console.print(f"[dim]Debug: error_code={last_error}, error_txt={last_error_txt}[/dim]")
            
            if is_allowed:
                self.console.print("[red]✗[/red] Write failed (see debug info above)")
            else:
                self.console.print("[green]✓[/green] Write was blocked by firewall (as expected)")
    
    def write_single_register(self, address: int, value: int):
        """Write single register (FC 06)"""
        self.console.print(f"\n[yellow]⚠ Attempting to write register {address} = {value}...[/yellow]")
        
        is_allowed = self.is_operation_allowed(ModbusFunctionCode.WRITE_SINGLE_REGISTER)
        if not is_allowed:
            self.console.print("[dim]This operation is blocked by security policy[/dim]")
        
        result = self.client.write_single_register(address, value)
        
        if result:
            self.console.print(f"[green]✓[/green] Write succeeded! Register {address} set to {value}")
        else:
            if is_allowed:
                self.console.print("[red]✗[/red] Write failed (connection issue)")
            else:
                self.console.print("[green]✓[/green] Write was blocked by firewall (as expected)")
    
    def write_multiple_registers(self, start_addr: int, values: list):
        """Write multiple registers (FC 16)"""
        self.console.print(f"\n[yellow]⚠ Attempting to write {len(values)} registers from address {start_addr}...[/yellow]")
        self.console.print(f"[dim]Values: {values}[/dim]")
        
        is_allowed = self.is_operation_allowed(ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS)
        if not is_allowed:
            self.console.print("[dim]This operation is blocked by security policy[/dim]")
        
        result = self.client.write_multiple_registers(start_addr, values)
        
        if result:
            self.console.print(f"[green]✓[/green] Write succeeded! Registers {start_addr}-{start_addr + len(values) - 1} updated")
        else:
            if is_allowed:
                self.console.print("[red]✗[/red] Write failed (connection issue)")
            else:
                self.console.print("[green]✓[/green] Write was blocked by firewall (as expected)")
    
    def write_multiple_coils(self, start_addr: int, values: list):
        """Write multiple coils (FC 15)"""
        self.console.print(f"\n[yellow]⚠ Attempting to write {len(values)} coils from address {start_addr}...[/yellow]")
        self.console.print(f"[dim]Values: {values}[/dim]")
        
        is_allowed = self.is_operation_allowed(ModbusFunctionCode.WRITE_MULTIPLE_COILS)
        if not is_allowed:
            self.console.print("[dim]This operation is blocked by security policy[/dim]")
        
        result = self.client.write_multiple_coils(start_addr, values)
        
        if result:
            self.console.print(f"[green]✓[/green] Write succeeded! Coils {start_addr}-{start_addr + len(values) - 1} updated")
        else:
            if is_allowed:
                self.console.print("[red]✗[/red] Write failed (connection issue)")
            else:
                self.console.print("[green]✓[/green] Write was blocked by firewall (as expected)")
    
    def validate_address(self, addr: int, max_addr: int = 65535) -> bool:
        """Validate Modbus address range"""
        if addr < 0 or addr > max_addr:
            self.console.print(f"[red]Invalid address: must be 0-{max_addr}[/red]")
            return False
        return True
    
    def validate_count(self, count: int, max_count: int = 125) -> bool:
        """Validate Modbus read/write count"""
        if count < 1 or count > max_count:
            self.console.print(f"[red]Invalid count: must be 1-{max_count}[/red]")
            return False
        return True
    
    def run_interactive(self):
        """Run interactive menu with READ and WRITE sections"""
        self.console.print(Panel(
            "[bold cyan]Modbus HMI Client[/bold cyan]\n"
            "[dim]Thermal Power Plant - Interactive Control Interface[/dim]",
            border_style="cyan"
        ))
        
        # Only connect if client not already set (HTTP mode sets it externally)
        if self.client is None:
            if not self.connect():
                return
        
        while True:
            # Display menu with READ and WRITE sections
            self.console.print("\n" + "="*50)
            self.console.print("[bold blue]📘 READ OPERATIONS[/bold blue]")
            self.console.print("="*50)
            self.console.print(f"  [1] Read Coils (FC 01)             {self.get_operation_status(ModbusFunctionCode.READ_COILS)}")
            self.console.print(f"  [2] Read Discrete Inputs (FC 02)   {self.get_operation_status(ModbusFunctionCode.READ_DISCRETE_INPUTS)}")
            self.console.print(f"  [3] Read Holding Registers (FC 03) {self.get_operation_status(ModbusFunctionCode.READ_HOLDING_REGISTERS)}")
            self.console.print(f"  [4] Read Input Registers (FC 04)   {self.get_operation_status(ModbusFunctionCode.READ_INPUT_REGISTERS)}")
            
            self.console.print("\n" + "="*50)
            self.console.print("[bold yellow]✍️  WRITE OPERATIONS[/bold yellow]")
            self.console.print("="*50)
            self.console.print(f"  [5] Write Coils (FC 05/15)         {self.get_operation_status(ModbusFunctionCode.WRITE_SINGLE_COIL)}")
            self.console.print(f"  [6] Write Registers (FC 06/16)     {self.get_operation_status(ModbusFunctionCode.WRITE_SINGLE_REGISTER)}")
            
            self.console.print("\n" + "="*50)
            self.console.print("[bold white]⚙️  OTHER[/bold white]")
            self.console.print("="*50)
            self.console.print("  [7] Run All Tests")
            self.console.print("  [8] Show Security Policy")
            self.console.print("  [0] Exit")
            
            try:
                choice = Prompt.ask("\n[bold]Select operation[/bold]", default="0")
                
                # === READ OPERATIONS ===
                if choice == "1":
                    self.console.print("\n[bold cyan]Read Coils (FC 01)[/bold cyan]")
                    addr = IntPrompt.ask("  Start address", default=0)
                    if not self.validate_address(addr): continue
                    count = IntPrompt.ask("  Number of coils to read", default=8)
                    if not self.validate_count(count, 2000): continue
                    self.read_coils(addr, count)
                    
                elif choice == "2":
                    self.console.print("\n[bold cyan]Read Discrete Inputs (FC 02)[/bold cyan]")
                    addr = IntPrompt.ask("  Start address", default=0)
                    if not self.validate_address(addr): continue
                    count = IntPrompt.ask("  Number of discrete inputs to read", default=8)
                    if not self.validate_count(count, 2000): continue
                    self.read_discrete_inputs(addr, count)
                    
                elif choice == "3":
                    self.console.print("\n[bold cyan]Read Holding Registers (FC 03)[/bold cyan]")
                    addr = IntPrompt.ask("  Start address", default=0)
                    if not self.validate_address(addr): continue
                    count = IntPrompt.ask("  Number of holding registers to read", default=9)
                    if not self.validate_count(count, 125): continue
                    self.read_holding_registers(addr, count)
                    
                elif choice == "4":
                    self.console.print("\n[bold cyan]Read Input Registers (FC 04)[/bold cyan]")
                    addr = IntPrompt.ask("  Start address", default=0)
                    if not self.validate_address(addr): continue
                    count = IntPrompt.ask("  Number of input registers to read", default=8)
                    if not self.validate_count(count, 125): continue
                    self.read_input_registers(addr, count)
                
                # === WRITE OPERATIONS ===
                elif choice == "5":
                    self.console.print("\n[bold yellow]Write Coils (FC 05/15)[/bold yellow]")
                    addr = IntPrompt.ask("  Start address", default=0)
                    if not self.validate_address(addr): continue
                    count = IntPrompt.ask("  Number of coils to write", default=1)
                    if not self.validate_count(count, 1968): continue
                    
                    if count == 1:
                        # Single coil write (FC 05)
                        val_str = Prompt.ask("  Value (ON/OFF or 1/0)", default="ON")
                        val = val_str.upper() in ("ON", "TRUE", "1", "YES")
                        self.write_single_coil(addr, val)
                    else:
                        # Multiple coil write (FC 15)
                        self.console.print(f"  [dim]Enter {count} values (ON/OFF or 1/0), comma-separated:[/dim]")
                        val_str = Prompt.ask("  Values", default=",".join(["OFF"]*count))
                        values = []
                        for v in val_str.split(","):
                            v = v.strip().upper()
                            values.append(v in ("ON", "TRUE", "1", "YES"))
                        if len(values) != count:
                            self.console.print(f"[red]Expected {count} values, got {len(values)}[/red]")
                            continue
                        self.write_multiple_coils(addr, values)
                    
                elif choice == "6":
                    self.console.print("\n[bold yellow]Write Registers (FC 06/16)[/bold yellow]")
                    addr = IntPrompt.ask("  Start address", default=0)
                    if not self.validate_address(addr): continue
                    count = IntPrompt.ask("  Number of registers to write", default=1)
                    if not self.validate_count(count, 123): continue
                    
                    if count == 1:
                        # Single register write (FC 06)
                        val = IntPrompt.ask("  Value (0-65535)", default=0)
                        if val < 0 or val > 65535:
                            self.console.print("[red]Value must be 0-65535[/red]")
                            continue
                        self.write_single_register(addr, val)
                    else:
                        # Multiple register write (FC 16)
                        self.console.print(f"  [dim]Enter {count} values (0-65535), comma-separated:[/dim]")
                        val_str = Prompt.ask("  Values", default=",".join(["0"]*count))
                        try:
                            values = [int(v.strip()) for v in val_str.split(",")]
                            if len(values) != count:
                                self.console.print(f"[red]Expected {count} values, got {len(values)}[/red]")
                                continue
                            if any(v < 0 or v > 65535 for v in values):
                                self.console.print("[red]All values must be 0-65535[/red]")
                                continue
                            self.write_multiple_registers(addr, values)
                        except ValueError:
                            self.console.print("[red]Invalid number format[/red]")
                            continue
                
                # === OTHER ===
                elif choice == "7":
                    self.run_all_tests()
                elif choice == "8":
                    self.show_security_policy()
                elif choice == "0":
                    break
                else:
                    self.console.print("[red]Invalid choice[/red]")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
        
        self.disconnect()
    
    def show_security_policy(self):
        """Display current security policy configuration based on connection mode"""
        from core.config import get_function_code_name
        
        # Determine policy type
        if not self.is_remote:
            policy_name = "Local Security Policy"
            policy_desc = "Full access for local connections"
        elif self.is_admin:
            policy_name = "Remote Admin Security Policy"
            policy_desc = "Authenticated admin access"
        else:
            policy_name = "Remote Read-Only Policy"
            policy_desc = "Non-authenticated remote access"
        
        lines = [f"[bold cyan]{policy_name}[/bold cyan]"]
        lines.append(f"[dim]{policy_desc}[/dim]\n")
        lines.append(f"[dim]Access Level: {self.access_level}[/dim]\n")
        
        allowed = self.get_active_policy_allowed()
        blocked = self.get_active_policy_blocked()
        
        lines.append("[green]Allowed Function Codes:[/green]")
        for fc in sorted(allowed):
            lines.append(f"  • 0x{fc:02X}: {get_function_code_name(fc)}")
        
        lines.append("\n[red]Blocked Function Codes:[/red]")
        for fc in sorted(blocked):
            lines.append(f"  • 0x{fc:02X}: {get_function_code_name(fc)}")
        
        self.console.print(Panel("\n".join(lines), border_style="cyan"))
    
    def run_all_tests(self):
        """Run all tests sequentially"""
        self.console.print("\n[bold cyan]Running All Tests...[/bold cyan]")
        self.console.print("=" * 50)
        
        # Read operations (should succeed)
        self.console.print("\n[bold green]--- Read Operations (Should Pass) ---[/bold green]")
        self.read_coils(0, 5)
        time.sleep(0.5)
        self.read_discrete_inputs(0, 5)
        time.sleep(0.5)
        self.read_holding_registers(0, 6)
        time.sleep(0.5)
        self.read_input_registers(0, 6)
        time.sleep(0.5)
        
        # Write operations (should be blocked)
        self.console.print("\n[bold red]--- Write Operations (Should Be Blocked) ---[/bold red]")
        self.write_single_coil(0, True)
        time.sleep(0.5)
        self.write_single_register(0, 999)
        time.sleep(0.5)
        self.write_multiple_registers(0, [100, 200, 300])
        
        self.console.print("\n[bold cyan]Tests Complete![/bold cyan]")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Modbus HMI Client")
    parser.add_argument("--host", default="127.0.0.1", help="Firewall host address")
    parser.add_argument("--port", type=int, default=502, help="Firewall port")
    parser.add_argument("--remote", metavar="URL", help="Remote HTTP Bridge URL (e.g., https://xxx.loca.lt)")
    parser.add_argument("--test", action="store_true", help="Run automated tests")
    
    args = parser.parse_args()
    
    # Check if using remote HTTP mode
    if args.remote:
        from network.http_client import ModbusHttpClient
        console = Console()
        
        console.print(Panel(
            "[bold cyan]Remote Connection Mode[/bold cyan]\n"
            f"[dim]URL: {args.remote}[/dim]",
            border_style="cyan"
        ))
        
        # Create HTTP client
        http_client = ModbusHttpClient(args.remote)
        
        if not http_client.open():
            console.print(f"[red]✗[/red] Failed to connect to HTTP Bridge")
            console.print(f"[dim]Error: {http_client.last_error_as_txt}[/dim]")
            return
        
        console.print(f"[green]✓[/green] Connected to HTTP Bridge\n")
        
        # Ask if user wants admin access
        admin_choice = Prompt.ask(
            "[bold yellow]Do you want to connect as Admin?[/bold yellow]",
            choices=["yes", "no"],
            default="no"
        )
        
        is_admin = False
        
        if admin_choice.lower() == "yes":
            # Admin authentication with 3 attempts
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                password = Prompt.ask(
                    f"[yellow]Enter Admin Password[/yellow] (Attempt {attempt}/{max_attempts})",
                    password=True
                )
                
                if http_client.authenticate(password):
                    console.print("[green]✓[/green] [bold]Authentication successful! Admin mode enabled.[/bold]")
                    is_admin = True
                    break
                else:
                    remaining = max_attempts - attempt
                    if remaining > 0:
                        console.print(f"[red]✗[/red] Invalid password. {remaining} attempts remaining.")
                        retry = Prompt.ask(
                            "  [dim]Options:[/dim]",
                            choices=["retry", "readonly"],
                            default="retry"
                        )
                        if retry == "readonly":
                            console.print("[yellow]ℹ[/yellow] Connecting in Read-Only mode...")
                            http_client.create_session()
                            break
                    else:
                        console.print("[red]✗[/red] All attempts failed. Connecting in Read-Only mode.")
                        http_client.create_session()
        else:
            # Read-only mode
            console.print("[yellow]ℹ[/yellow] Connecting in Read-Only mode...")
            http_client.create_session()
        
        # Create HMI with HTTP client
        hmi = ModbusHMI(host=args.host, port=args.port)
        hmi.client = http_client
        
        # Store access level for UI
        hmi.is_remote = True
        hmi.is_admin = is_admin
        hmi.access_level = "ADMIN" if is_admin else "READ-ONLY"
        
        # Show access level banner
        if is_admin:
            console.print(Panel(
                "[bold green]✓ ADMIN MODE[/bold green]\n"
                "[dim]Full read/write access enabled[/dim]",
                border_style="green"
            ))
        else:
            console.print(Panel(
                "[bold yellow]🔒 READ-ONLY MODE[/bold yellow]\n"
                "[dim]Write operations will be blocked[/dim]",
                border_style="yellow"
            ))
        
        if args.test:
            hmi.run_all_tests()
        else:
            hmi.run_interactive()
        
        http_client.close()
    else:
        # Normal TCP mode (local connection)
        console = Console()
        console.print(Panel(
            "[bold green]Local Connection Mode[/bold green]\n"
            "[dim]Full access - no authentication required[/dim]",
            border_style="green"
        ))
        
        hmi = ModbusHMI(host=args.host, port=args.port)
        hmi.is_remote = False
        hmi.is_admin = True
        hmi.access_level = "LOCAL"
        
        if args.test:
            if hmi.connect():
                hmi.run_all_tests()
                hmi.disconnect()
        else:
            hmi.run_interactive()


if __name__ == "__main__":
    main()
