"""
Modbus Firewall - Simulated PLC Server

A Modbus TCP server that simulates a PLC with various register types.
Features live-updating display with activity tracking.
"""

import time
import threading
import signal
import sys
import random
from datetime import datetime
from pyModbusTCP.server import ModbusServer, DataBank
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from config import DEFAULT_CONFIG


class ActivityTracker:
    """Tracks read/write activity on registers"""
    
    def __init__(self):
        self.last_access = {}  # {(type, addr): timestamp}
        self.access_count = {}  # {(type, addr): count}
    
    def record_access(self, reg_type: str, address: int):
        """Record an access to a register"""
        key = (reg_type, address)
        self.last_access[key] = datetime.now()
        self.access_count[key] = self.access_count.get(key, 0) + 1
    
    def get_status(self, reg_type: str, address: int) -> str:
        """Get activity status for a register"""
        key = (reg_type, address)
        if key not in self.last_access:
            return "[dim]idle[/dim]"
        
        elapsed = (datetime.now() - self.last_access[key]).total_seconds()
        count = self.access_count.get(key, 0)
        
        if elapsed < 2:
            return "[bold green]ACTIVE[/bold green]"
        elif elapsed < 10:
            return f"[yellow]{count}x[/yellow]"
        else:
            return f"[dim]{count}x[/dim]"


class SimulatedPLC:
    """Simulated PLC with dynamic process values and live display"""
    
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG.plc
        self.console = Console()
        self.running = False
        self.server = None
        self.simulation_thread = None
        
        # Activity tracker - now uses polling to detect changes
        self.activity_tracker = ActivityTracker()
        
        # Use standard DataBank (TrackedDataBank was breaking write handling)
        self.data_bank = DataBank()
        
        # Store previous values for change detection
        self.prev_coils = None
        self.prev_holding = None
        
        # Coil and register names for display (Thermal Power Plant)
        self.coil_names = {
            0: "Fuel_Motor",
            1: "Feedwater_Pump",
            2: "Steam_Valve",
            3: "Air_Fan",
            4: "Turbine_Enable",
            5: "Generator_Connect",
            6: "Plant_Run",
            7: "Alarm_Enable",
        }
        
        self.discrete_names = {
            0: "Boiler_Lvl_Hi",
            1: "Boiler_Lvl_Lo",
            2: "Boiler_Press_Hi",
            3: "Boiler_Press_Lo",
            4: "Boiler_Temp_Hi",
            5: "Turbine_Trip",
            6: "E-Stop_OK",
            7: "Fault_Active",
        }
        
        # Input registers: (Name, Unit, Scale factor)
        # Raw value / Scale = Scaled value
        self.input_reg_names = {
            0: ("Feedwater_Temp", "°C", 10),      # 320 -> 32.0 °C
            1: ("Feedwater_Press", "bar", 10),   # 650 -> 65.0 bar
            2: ("Boiler_Temp", "°C", 1),         # 850 -> 850 °C
            3: ("Boiler_Press", "bar", 1),       # 160 -> 160 bar
            4: ("Steam_Temp", "°C", 1),          # 540 -> 540 °C
            5: ("Steam_Press", "bar", 1),        # 150 -> 150 bar
            6: ("Turbine_Speed", "RPM", 1),      # 3000 -> 3000 RPM
            7: ("Gen_Frequency", "Hz", 10),      # 500 -> 50.0 Hz
        }
        
        # Holding registers: (Name, Unit, Scale factor)
        self.holding_reg_names = {
            0: ("Boiler_Temp_SP", "°C", 1),      # 850 -> 850 °C
            1: ("Boiler_Press_SP", "bar", 1),   # 160 -> 160 bar
            2: ("Steam_Temp_SP", "°C", 1),       # 540 -> 540 °C
            3: ("Steam_Press_SP", "bar", 1),    # 150 -> 150 bar
            4: ("Turbine_Spd_SP", "RPM", 1),    # 3000 -> 3000 RPM
            5: ("Gen_Load_SP", "%", 1),          # 80 -> 80%
            6: ("FW_Temp_SP", "°C", 10),         # 320 -> 32.0 °C
            7: ("FW_Press_SP", "bar", 10),      # 650 -> 65.0 bar
            8: ("Plant_Mode", "", 1),            # 0=Auto, 1=Manual
        }
        
    def initialize_registers(self):
        """Initialize register map with thermal power plant values"""
        # Coils (0x): Digital outputs - Power plant controls
        initial_coils = [False] * self.config.num_coils
        initial_coils[0] = True   # Fuel motor running
        initial_coils[1] = True   # Feedwater pump running
        initial_coils[3] = True   # Air fan running
        initial_coils[6] = True   # Plant run command ON
        self.data_bank.set_coils(0, initial_coils)
        
        # Discrete Inputs (1x): Protection status
        initial_discrete = [False] * self.config.num_discrete_inputs
        initial_discrete[6] = True   # Emergency stop OK
        self.data_bank.set_discrete_inputs(0, initial_discrete)
        
        # Input Registers (3x): Process measurements
        initial_input_regs = [
            320,   # 0: Feedwater Temp (32.0 °C)
            650,   # 1: Feedwater Pressure (65.0 bar)
            850,   # 2: Boiler Temp (850 °C)
            160,   # 3: Boiler Pressure (160 bar)
            540,   # 4: Steam Temp (540 °C)
            150,   # 5: Steam Pressure (150 bar)
            3000,  # 6: Turbine Speed (3000 RPM)
            500,   # 7: Generator Frequency (50.0 Hz)
        ] + [0] * (self.config.num_input_registers - 8)
        self.data_bank.set_input_registers(0, initial_input_regs)
        
        # Holding Registers (4x): Setpoints
        initial_holding_regs = [
            850,   # 0: Boiler Temp SP (850 °C)
            160,   # 1: Boiler Pressure SP (160 bar)
            540,   # 2: Steam Temp SP (540 °C)
            150,   # 3: Steam Pressure SP (150 bar)
            3000,  # 4: Turbine Speed SP (3000 RPM)
            80,    # 5: Generator Load SP (80%)
            320,   # 6: Feedwater Temp SP (32.0 °C)
            650,   # 7: Feedwater Pressure SP (65.0 bar)
            0,     # 8: Plant Mode (0=Auto)
        ] + [0] * (self.config.num_holding_registers - 9)
        self.data_bank.set_holding_registers(0, initial_holding_regs)
        
        # Initialize previous values for change detection
        self.prev_coils = list(self.data_bank.get_coils(0, 100) or [])
        self.prev_holding = list(self.data_bank.get_holding_registers(0, 100) or [])
    
    def detect_changes(self):
        """Detect changes in coils and holding registers for activity tracking"""
        current_coils = self.data_bank.get_coils(0, 100) or []
        current_holding = self.data_bank.get_holding_registers(0, 100) or []
        
        # Check for coil changes
        for i in range(min(len(current_coils), len(self.prev_coils))):
            if current_coils[i] != self.prev_coils[i]:
                self.activity_tracker.record_access("coil", i)
                self.prev_coils[i] = current_coils[i]
        
        # Check for holding register changes
        for i in range(min(len(current_holding), len(self.prev_holding))):
            if current_holding[i] != self.prev_holding[i]:
                self.activity_tracker.record_access("holding", i)
                self.prev_holding[i] = current_holding[i]
    
    def simulate_process(self):
        """Background thread to simulate dynamic power plant process values"""
        while self.running:
            try:
                current = self.data_bank.get_input_registers(0, 8)
                if current:
                    # Simulate realistic power plant fluctuations
                    current[0] = max(300, min(340, current[0] + random.randint(-2, 2)))   # Feedwater Temp (30-34°C)
                    current[1] = max(630, min(670, current[1] + random.randint(-5, 5)))   # Feedwater Press (63-67 bar)
                    current[2] = max(840, min(860, current[2] + random.randint(-3, 3)))   # Boiler Temp (840-860°C)
                    current[3] = max(155, min(165, current[3] + random.randint(-1, 1)))   # Boiler Press (155-165 bar)
                    current[4] = max(535, min(545, current[4] + random.randint(-2, 2)))   # Steam Temp (535-545°C)
                    current[5] = max(145, min(155, current[5] + random.randint(-1, 1)))   # Steam Press (145-155 bar)
                    current[6] = max(2990, min(3010, current[6] + random.randint(-5, 5))) # Turbine Speed (~3000 RPM)
                    current[7] = max(498, min(502, current[7] + random.randint(-1, 1)))   # Gen Freq (49.8-50.2 Hz)
                    # Don't use set_ method to avoid marking as "active" from simulation
                    DataBank.set_input_registers(self.data_bank, 0, current)
                
                time.sleep(self.config.update_interval)
            except Exception as e:
                break
    
    def generate_display(self) -> Table:
        """Generate the live display table"""
        # Create main layout
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column()
        
        # === COILS TABLE ===
        coils_table = Table(title="[bold cyan]Coils (FC 01/05)[/bold cyan]", 
                           box=None, show_header=True, header_style="bold")
        coils_table.add_column("Addr", justify="right", width=5)
        coils_table.add_column("Name", width=12)
        coils_table.add_column("Value", width=8)
        
        coils = self.data_bank.get_coils(0, 20) or []
        for i in range(min(20, len(coils))):
            name = self.coil_names.get(i, f"Coil {i}")
            val = "[green]ON[/green]" if coils[i] else "[red]OFF[/red]"
            coils_table.add_row(str(i), name, val)
        
        # === DISCRETE INPUTS TABLE ===
        discrete_table = Table(title="[bold cyan]Discrete Inputs (FC 02)[/bold cyan]", 
                              box=None, show_header=True, header_style="bold")
        discrete_table.add_column("Addr", justify="right", width=5)
        discrete_table.add_column("Name", width=12)
        discrete_table.add_column("Value", width=8)
        
        discrete = self.data_bank.get_discrete_inputs(0, 10) or []
        for i in range(min(10, len(discrete))):
            name = self.discrete_names.get(i, f"DI {i}")
            val = "[green]ON[/green]" if discrete[i] else "[dim]OFF[/dim]"
            discrete_table.add_row(str(i), name, val)
        
        # === INPUT REGISTERS TABLE ===
        input_table = Table(title="[bold cyan]Input Registers (FC 04)[/bold cyan]", 
                           box=None, show_header=True, header_style="bold")
        input_table.add_column("Addr", justify="right", width=5)
        input_table.add_column("Name", width=12)
        input_table.add_column("Raw", justify="right", width=6)
        input_table.add_column("Scaled", justify="right", width=12)
        
        input_regs = self.data_bank.get_input_registers(0, 10) or []
        for i in range(min(10, len(input_regs))):
            if i in self.input_reg_names:
                name, unit, scale = self.input_reg_names[i]
                scaled = f"{input_regs[i]/scale:.1f} {unit}"
            else:
                name = f"IR {i}"
                scaled = str(input_regs[i])
            input_table.add_row(str(i), name, str(input_regs[i]), scaled)
        
        # === HOLDING REGISTERS TABLE ===
        holding_table = Table(title="[bold cyan]Holding Registers (FC 03/06/16)[/bold cyan]", 
                             box=None, show_header=True, header_style="bold")
        holding_table.add_column("Addr", justify="right", width=5)
        holding_table.add_column("Name", width=12)
        holding_table.add_column("Raw", justify="right", width=6)
        holding_table.add_column("Scaled", justify="right", width=12)
        
        holding_regs = self.data_bank.get_holding_registers(0, 20) or []
        for i in range(min(20, len(holding_regs))):
            if i in self.holding_reg_names:
                name, unit, scale = self.holding_reg_names[i]
                if i == 5:
                    scaled = "Auto" if holding_regs[i] == 0 else "Manual"
                elif unit:
                    scaled = f"{holding_regs[i]/scale:.1f} {unit}"
                else:
                    scaled = str(holding_regs[i])
            else:
                name = f"HR {i}"
                scaled = str(holding_regs[i])
            holding_table.add_row(str(i), name, str(holding_regs[i]), scaled)
        
        # Combine tables
        left = Table.grid()
        left.add_row(coils_table)
        left.add_row("")
        left.add_row(discrete_table)
        
        right = Table.grid()
        right.add_row(input_table)
        right.add_row("")
        right.add_row(holding_table)
        
        grid.add_row(left, right)
        
        return Panel(
            grid,
            title=f"[bold]PLC Registers[/bold] | {self.config.host}:{self.config.port} | {datetime.now().strftime('%H:%M:%S')}",
            border_style="cyan"
        )
    
    def start(self):
        """Start the PLC server with live display"""
        self.console.print(Panel(
            f"[bold cyan]Simulated PLC Server[/bold cyan]\n"
            f"[dim]Modbus TCP Server with Live Display[/dim]",
            border_style="cyan"
        ))
        
        # Initialize registers
        self.initialize_registers()
        
        # Create and start server
        self.server = ModbusServer(
            host=self.config.host,
            port=self.config.port,
            data_bank=self.data_bank,
            no_block=True
        )
        
        self.console.print(f"[green]✓[/green] Starting server on {self.config.host}:{self.config.port}")
        
        try:
            self.server.start()
            self.running = True
            
            # Start simulation thread
            self.simulation_thread = threading.Thread(target=self.simulate_process, daemon=True)
            self.simulation_thread.start()
            
            self.console.print(f"[green]✓[/green] Server running. Press Ctrl+C to stop.\n")
            
            # Live display loop
            with Live(self.generate_display(), refresh_per_second=2, console=self.console) as live:
                while self.running:
                    self.detect_changes()  # Poll for external writes
                    live.update(self.generate_display())
                    time.sleep(0.5)
                    
        except Exception as e:
            self.console.print(f"[red]✗[/red] Error: {e}")
            return False
        
        return True
    
    def stop(self):
        """Stop the PLC server"""
        self.running = False
        if self.server:
            self.server.stop()
        self.console.print("\n[yellow]Server stopped.[/yellow]")


def main():
    """Main entry point"""
    plc = SimulatedPLC()
    
    def signal_handler(sig, frame):
        plc.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    plc.start()


if __name__ == "__main__":
    main()

