#!/usr/bin/env python3
"""
Cross-Platform Package Scanner Launcher
Works on Windows, macOS, and Linux
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def find_bash():
    """Find bash executable on the system"""
    system = platform.system()
    
    if system == "Windows":
        # Try common Windows bash locations
        locations = [
            "bash",  # Git Bash in PATH
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ]
        
        for loc in locations:
            try:
                subprocess.run([loc, "--version"], 
                             capture_output=True, check=True, timeout=5)
                return loc
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        # Try WSL
        try:
            subprocess.run(["wsl", "--status"], 
                         capture_output=True, check=True, timeout=5)
            return "wsl bash"
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        return None
    else:
        # Unix-like systems (macOS, Linux)
        return "bash"


def main():
    script_dir = Path(__file__).parent
    
    print("╔══════════════════════════════════════════════════════════╗")
    print("║       Package Security Scanner - Launcher               ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print("Select scanner type:")
    print("  1. Python Package Scanner (PyPI)")
    print("  2. npm Package Scanner (npm/Node.js)")
    print("  3. Exit")
    print()
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == "3":
        print("Exiting...")
        sys.exit(0)
    
    if choice not in ["1", "2"]:
        print(f"Invalid choice: {choice}")
        sys.exit(1)
    
    # Determine which script to run
    if choice == "1":
        script_name = "pkg_scan.sh"
        scanner_name = "Python Package Scanner"
    else:
        script_name = "npm_scan.sh"
        scanner_name = "npm Package Scanner"
    
    bash_script = script_dir / "main_script" / script_name
    
    if not bash_script.exists():
        print(f"ERROR: Script not found: {bash_script}")
        sys.exit(1)
    
    # Find bash
    bash_cmd = find_bash()
    
    if not bash_cmd:
        print()
        print("ERROR: bash not found!")
        print()
        print("This tool requires bash to run. Please install:")
        if platform.system() == "Windows":
            print("  - Git for Windows: https://git-scm.com/download/win")
            print("  - OR Windows Subsystem for Linux (WSL): Run 'wsl --install' in PowerShell as Admin")
        else:
            print("  - bash shell (should be pre-installed on macOS/Linux)")
        sys.exit(1)
    
    print()
    print(f"Starting {scanner_name}...")
    print("=" * 60)
    print()
    
    # Run the bash script
    try:
        if bash_cmd == "wsl bash":
            # WSL needs special handling
            result = subprocess.run(
                ["wsl", "bash", str(bash_script)],
                check=False
            )
        else:
            # Make script executable on Unix-like systems
            if platform.system() != "Windows":
                try:
                    os.chmod(bash_script, 0o755)
                except OSError:
                    pass
            
            result = subprocess.run(
                [bash_cmd, str(bash_script)],
                check=False
            )
        
        sys.exit(result.returncode)
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: Failed to run scanner: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
