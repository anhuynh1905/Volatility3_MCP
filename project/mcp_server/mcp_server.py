import os
import sys
import subprocess
import json
import shlex
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import asyncio
from fastmcp import FastMCP
from utils import ubuntu_symbols_finder as usf

VOL_EXE = "python3"
VOL_SCRIPT= "/app/volatility3/vol.py"
cwd= "/app/02_working"
cwd_symbols= "/app/Ubuntu_symbols"
SYMBOLS="/app/volatility3/volatility3/symbols/linux"
BANNER_PATTERN = r"0x[0-9a-f]+\s+(Linux version .*)"

#Set name and instruction for LLM
mcp = FastMCP(name="Volitality 3 MCP Server for Windows")
server_instruction = FastMCP(
    name="Volitality3",
    instructions="""
        This server provides Volatility 3 tools for ram forensic on Windows and Linux.
        REMEMBER TO ALWAYS CHECK IF YOU ARE WORKING WITH WINDOWS OR LINUX. 
        For LINUX ALWAYS CHECK IF YOU NEED SYMBOLS OR NOT.
        Call get_info() to get Volatility 3 info.
    """,
)

#Check the existing of symbols file
async def check_symbol_file_exists(ddeb_filename_without_extension: str) -> bool:
    expected_filename = f"{ddeb_filename_without_extension}.json.xz"
    full_path = os.path.join(SYMBOLS, expected_filename) 

    file_exists = await asyncio.to_thread(os.path.exists, full_path)
    return file_exists

#Run Volatility 3
async def run_volatility(cmd_args):
    cmd = [ VOL_EXE, VOL_SCRIPT ] + cmd_args

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            stderr_text = stderr.decode('utf-8', errors='replace')
            return f"Error running Volatility command: {stderr_text}"
        
        return stdout.decode('utf-8', errors='replace')
    except Exception as e:
        return f"Exception running Volatility: {str(e)}"

#Automatic get symbols for linux
async def get_symbols(banners: str) -> str:
    commands, ddeb_filename_without_extension = usf.find_symbols(banners)

    check = await check_symbol_file_exists(ddeb_filename_without_extension)
    if check:
        return f"Symbols for kernel '{banners}' are ready at {SYMBOLS}."

    for command in commands:
        needs_shell = "|" in command or ">" in command

        if not needs_shell:
            args = shlex.split(command)
        else:
            args = ["sh", "-c", command] 
            
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd_symbols
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return f"Error Output:\n{stderr.decode('utf-8', errors='replace')}"
            
        except FileNotFoundError:
            return f"FAILED: Executable not found for command starting with '{args[0]}'"
        except Exception as e:
            return f"FAILED: An unexpected error occurred: {e}"
    return "Success adding the Linux symbols"


#Volatility 3 tools Windows
@mcp.tool()
async def get_info() -> str:
    """Get Volatility 3 version and list all available plugins"""
    return await run_volatility(["-h"])

@mcp.tool()
async def get_image_info_windows(memory_dump_path: str) -> str:
    """Get Windows Image Info"""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    return await run_volatility(["-f", memory_dump_path, "windows.info.Info"])

@mcp.tool()
async def run_pstree(memory_dump_path: str) -> str:
    """Helps to display the parent-child relationships between processes."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.pstree.PsTree"])

@mcp.tool()
async def run_pslist(memory_dump_path: str) -> str:
    """Helps list the processes running while the memory dump was taken."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.pslist.PsList"])

@mcp.tool()
async def run_psscan(memory_dump_path: str) -> str:
    """Scans for processes present in a particular windows memory image."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.psscan.PsScan"])

@mcp.tool()
async def run_netscan(memory_dump_path: str) -> str:
    """Scans for network objects present in a particular windows memory image."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.netscan.NetScan"])

@mcp.tool()
async def run_malfind(memory_dump_path: str, dump_dir: Optional[str] = None) -> str:
    """Lists process memory ranges that potentially contain injected code"""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    cmd_args = ["-f", memory_dump_path, "windows.malfind.Malfind"]
    
    if dump_dir:
        dump_dir = os.path.normpath(dump_dir)
        if not os.path.isdir(dump_dir):
            try:
                os.makedirs(dump_dir)
            except Exception as e:
                return f"Error creating dump directory: {str(e)}"
        cmd_args.extend(["--dump-dir", dump_dir])
    
    result = await run_volatility(cmd_args)
    
    if dump_dir and os.path.exists(dump_dir):
        dumped_files = os.listdir(dump_dir)
        if dumped_files:
            result += f"\n\nDumped {len(dumped_files)} suspicious memory sections to {dump_dir}"
    
    return result

@mcp.tool()
async def run_cmdline(memory_dump_path: str) -> str:
    """Lists process command line arguments."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.cmdline.CmdLine"])

@mcp.tool()
async def run_dlllist(memory_dump_path: str, pid: Optional[int] = None) -> str:
    """Lists the loaded DLLs in a particular windows memory image."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    cmd_args = ["-f", memory_dump_path, "windows.dlllist.DllList"]
    
    if pid is not None:
        cmd_args.extend(["--pid", str(pid)])
    
    return await run_volatility(cmd_args)

@mcp.tool()
async def run_handles(memory_dump_path: str, pid: Optional[int] = None) -> str:
    """Lists process open handles."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    cmd_args = ["-f", memory_dump_path, "windows.handles.Handles"]
    
    if pid is not None:
        cmd_args.extend(["--pid", str(pid)])
    
    return await run_volatility(cmd_args)

@mcp.tool()
async def run_memmap(memory_dump_path: str, pid: int) -> str:
    """Prints the memory map"""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.memmap.Memmap", "--pid", str(pid)])

#Volatility 3 tools Linux
@mcp.tool()
async def run_pstree_linux(memory_dump_path: str) -> str:
    """Plugin for listing processes in a tree based on their parent process ID."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    return await run_volatility(["-f", memory_dump_path, "linux.pstree.PsTree"])

@mcp.tool()
async def run_pslist_linux(memory_dump_path: str) -> str:
    """Lists the processes present in a particular linux memory image."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    return await run_volatility(["-f", memory_dump_path, "linux.pslist.PsList"])

@mcp.tool()
async def run_psscan_linux(memory_dump_path: str) -> str:
    """Scans for processes present in a particular linux image."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    return await run_volatility(["-f", memory_dump_path, "linux.psscan.PsScan"])

@mcp.tool()
async def run_sockstat_linux(memory_dump_path: str) -> str:
    """Lists all network connections for all processes."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    return await run_volatility(["-f", memory_dump_path, "linux.sockstat.Sockstat"])

@mcp.tool()
async def run_Malfind_linux(memory_dump_path: str) -> str:
    """Lists process memory ranges that potentially contain injected code."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    return await run_volatility(["-f", memory_dump_path, "linux.malware.malfind.Malfind"])

@mcp.tool()
async def run_bash_linux(memory_dump_path: str, pid: Optional[str] = None) -> str:
    """Lists process memory ranges that potentially contain injected code."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    return await run_volatility(["-f", memory_dump_path, "linux.bash.Bash"])

@mcp.tool()
async def plugin_help(plugin_name: str) -> str:
    """Help to use the plugin"""
    return await run_volatility(plugin_name, "h")

@mcp.tool()
async def get_linux_symbols(memory_dump_path: str) -> str:
    """Get the linux symbols for Volatility"""
    output = await run_volatility(["-f", memory_dump_path, "banners"]) 
    banners = None

    for line in output.splitlines():
        match = re.search(BANNER_PATTERN, line) 

        if match:
            banners = match.group(1).strip()
            break

    return await get_symbols(banners) 


#Some helper tools

@mcp.tool()
async def run_filescan(memory_dump_path: str) -> str:
    """Scans for file objects present in a particular windows memory image."""
    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
    
    return await run_volatility(["-f", memory_dump_path, "windows.filescan.FileScan"])

@mcp.tool()
async def run_custom_plugin(memory_dump_path: str, plugin_name: str, additional_args: str = "") -> str:

    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"
  
    cmd_args = ["-f", memory_dump_path, plugin_name]

    if additional_args:
        cmd_args.extend(additional_args.split())
    
    return await run_volatility(cmd_args)

@mcp.tool()
async def list_memory_dumps(search_dir: str = None) -> str:
    """Listing memory dumps file in a folder"""
    if not search_dir:
        search_dir = os.getcwd()
    
    search_dir = os.path.normpath(search_dir)
    if not os.path.isdir(search_dir):
        return f"Error: Directory not found at {search_dir}"
  
    memory_extensions = ['.raw', '.vmem', '.dmp', '.mem', '.bin', '.img', '.001', '.dump', '.lime', '.elf']
    memory_files = []
    
    for root, _, files in os.walk(search_dir):
        for file in files:
            if any(file.lower().endswith(ext) for ext in memory_extensions):
                full_path = os.path.join(root, file)
                size_mb = os.path.getsize(full_path) / (1024 * 1024)
                memory_files.append(f"{full_path} (Size: {size_mb:.2f} MB)")
    
    if not memory_files:
        return f"No memory dump files found in {search_dir}"
    
    return "Found memory dump files:\n" + "\n".join(memory_files)

#Resource for MCP
@mcp.resource("volatility://plugins")
async def get_volatility_plugins() -> str:

    output = await run_volatility(["-h"])

    plugins = []
    capture = False
    for line in output.split('\n'):
        if line.strip() == "Plugins":
            capture = True
            continue
        if capture and line.strip() == "":
            capture = False
            break
        if capture:
            plugins.append(line.strip())
    
    return json.dumps(plugins, indent=2)

@mcp.resource("volatility://help/{plugin}")
async def get_plugin_help(plugin: str) -> str:
   
    return await run_volatility([plugin, "--help"])

#Prompt
@mcp.prompt()
def forensics_investigation_guide():
    """
    Comprehensive guide for conducting memory forensics investigations using Volatility3 MCP Server.
    Use this prompt to understand the systematic approach to memory analysis.
    """
    return """
# Memory Forensics Investigation Guide - Volatility3 MCP Server

You are a memory forensics expert with access to Volatility3 tools for analyzing Windows and Linux memory dumps.

## CRITICAL RULES:

1. **ALWAYS identify the OS type first** - Use get_image_info_windows() or check file type
2. **For Linux dumps**: ALWAYS run get_linux_symbols() before other analysis to ensure proper symbol resolution
3. **Use full absolute paths**: /app/02_working/filename.raw (never relative paths)
4. **Be systematic**: Follow the investigation workflow step-by-step
5. **Cross-reference findings**: Correlate process, network, and file data for comprehensive analysis

## INVESTIGATION WORKFLOW:

### Phase 1: DISCOVERY & RECONNAISSANCE
```
1. List available dumps: list_memory_dumps("/app/02_working")
2. Identify OS type: Check filename or use get_image_info_windows()
3. For Linux: Run get_linux_symbols(memory_dump_path) FIRST
4. Get basic info: get_info() to see all available plugins
```

### Phase 2: PROCESS ANALYSIS
```
Windows:
- run_pslist(path) - List all processes
- run_pstree(path) - View process hierarchy
- run_psscan(path) - Find hidden processes (compare with pslist!)
- run_cmdline(path) - Extract command line arguments

Linux:
- run_pslist_linux(path) - List all processes
- run_pstree_linux(path) - View process hierarchy  
- run_psscan_linux(path) - Find hidden processes

RED FLAGS:
- Processes with suspicious parent relationships (e.g., cmd.exe spawning from notepad.exe)
- Misspelled system processes (svchost.exe vs svch0st.exe)
- Processes running from temp directories (%TEMP%, /tmp)
- Unexpected processes with network connections
```

### Phase 3: MALWARE DETECTION
```
Windows:
- run_malfind(path) - Detect injected code, check for RWX memory regions
- run_malfind(path, dump_dir="/app/02_working/dumps") - Extract suspicious regions

Linux:
- run_Malfind_linux(path) - Detect injected code in Linux processes

INDICATORS OF COMPROMISE:
- Memory regions with Execute+Write permissions (RWX)
- Packed/encoded shellcode patterns (MZ headers in unexpected places)
- Process hollowing (legitimate process with malicious code)
- DLL injection, reflective loading
```

### Phase 4: NETWORK FORENSICS
```
Windows:
- run_netscan(path) - Enumerate all network connections
  
Linux:
- run_sockstat_linux(path) - List network connections per process

USPICIOUS PATTERNS:
- Connections to unusual ports (not 80, 443, 22, etc.)
- Connections to suspicious IPs (check threat intelligence)
- Processes that shouldn't have network activity (notepad.exe, calc.exe)
- Reverse shells, C2 beaconing patterns
```

### Phase 5: ARTIFACT RECOVERY
```
Windows:
- run_cmdline(path) - Command history
- run_filescan(path) - Recently accessed files
- run_handles(path, pid=XXX) - File handles for specific process

Linux:
- run_bash_linux(path) - Bash command history (CRITICAL for Linux investigations)

LOOK FOR:
- PowerShell/CMD commands indicating lateral movement
- File access patterns (ransomware, data exfiltration)
- Persistence mechanisms (scheduled tasks, registry modifications)
```

### Phase 6: DEEP DIVE ON SUSPICIOUS PIDs
```
For each suspicious PID found:

Windows:
1. run_dlllist(path, pid=XXX) - Check loaded DLLs for malicious libraries
2. run_handles(path, pid=XXX) - See what files/registry keys it's accessing
3. run_memmap(path, pid=XXX) - Analyze memory layout
4. run_malfind(path, dump_dir="...") - Dump suspicious memory for reverse engineering

Linux:
1. run_bash_linux(path) - Check what commands were executed
2. run_custom_plugin(path, "linux.proc.Maps") - Memory mappings
3. run_custom_plugin(path, "linux.lsof.Lsof") - Open files
```

### Phase 7: ADVANCED ANALYSIS
```
Use run_custom_plugin() for specialized analysis:

Registry (Windows):
- run_custom_plugin(path, "windows.registry.hivelist.HiveList")
- run_custom_plugin(path, "windows.registry.userassist.UserAssist")

Kernel Analysis:
- run_custom_plugin(path, "windows.modules.Modules") - Kernel drivers
- run_custom_plugin(path, "linux.lsmod.Lsmod") - Kernel modules
- run_custom_plugin(path, "linux.malware.check_syscall.Check_syscall") - Syscall hooks

Persistence:
- run_custom_plugin(path, "windows.registry.scheduled_tasks.ScheduledTasks")
- run_custom_plugin(path, "linux.malware.check_modules.Check_modules")
```

## REPORTING REQUIREMENTS:

After investigation, provide:

1. **Executive Summary**
   - Threat level (Critical/High/Medium/Low)
   - Key findings in 3-5 bullet points
   - Recommended immediate actions

2. **Technical Analysis**
   - Detailed process analysis with PIDs
   - Network connections with IPs and ports
   - Malware indicators (injected code, suspicious DLLs)
   - Timeline of events

3. **Indicators of Compromise (IOCs)**
   - File paths and names
   - Process names and command lines
   - Network indicators (IPs, domains, ports)
   - Registry keys (Windows) or file paths (Linux)

4. **Recommendations**
   - Containment steps
   - Eradication procedures
   - Recovery actions
   - Prevention measures

## AVAILABLE TOOLS SUMMARY:

**Core Tools:**
- get_info(), plugin_help(), list_memory_dumps(), get_linux_symbols()

**Windows Tools:**
- get_image_info_windows(), run_pslist(), run_pstree(), run_psscan()
- run_malfind(), run_cmdline(), run_dlllist(), run_handles(), run_memmap()
- run_netscan(), run_filescan()

**Linux Tools:**
- run_pslist_linux(), run_pstree_linux(), run_psscan_linux()
- run_Malfind_linux(), run_bash_linux(), run_sockstat_linux()

**Universal:**
- run_custom_plugin() - Access ALL 200+ Volatility plugins

## PRO TIPS:

1. **Compare outputs**: Always compare psscan vs pslist to find hidden processes
2. **Follow the process tree**: Unusual parent-child relationships are red flags
3. **Timeline correlation**: Match network activity timing with process creation
4. **Volatility is read-only**: All analysis is non-destructive, safe to experiment
5. **When in doubt, dump it**: Extract suspicious memory regions for deeper analysis
6. **Check plugin help**: Use plugin_help(plugin_name) for detailed options

## COMMON ATTACK PATTERNS TO RECOGNIZE:

- **Process Injection**: svchost.exe with unusual DLLs or memory regions
- **Credential Dumping**: lsass.exe with suspicious handles or memory access
- **Lateral Movement**: psexec, wmic, or PowerShell with network connections
- **Persistence**: New services, scheduled tasks, or registry autoruns
- **Data Exfiltration**: Large outbound network transfers, compression utilities
- **Rootkits**: Hidden processes (psscan vs pslist mismatch), kernel hooks

Remember: You're not just running tools, you're conducting forensic investigations.
Think critically, follow evidence chains, and build a comprehensive picture of what happened.

Memory dumps location: /app/02_working/
Linux symbols location: /app/Ubuntu_symbols/

Good hunting! 
"""

#Run the server
if __name__ == "__main__":
    # This runs the server, we will use HTTP
    mcp.run(transport="http", host="0.0.0.0", port=8000, path="/Volatility3")