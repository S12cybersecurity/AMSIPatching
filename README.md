# AMSI Bypass Tool
A Windows C++ utility that patches AMSI scanning functions in a target PowerShell process to bypass malware scanning.

## Overview
This tool identifies a running PowerShell process and patches the AMSI (Antimalware Scan Interface) functions to return an error code, effectively disabling AMSI protection for that process. This allows execution of PowerShell scripts that might otherwise be blocked by security software.

## Features
- Locates running PowerShell processes by name
- Identifies AMSI functions in the remote process memory
- Patches AmsiScanBuffer and AmsiScanString functions to return E_INVALIDARG
- Works on both 32-bit and 64-bit processes

## Usage
- Compile the tool using a C++ compiler
- Run with administrator privileges (required for process manipulation)
- The tool will automatically find the first running PowerShell process and patch its AMSI functions
