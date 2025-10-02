import os
import sys
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import asyncio
import re
from utils import ubuntu_symbols_finder as usf 
from fastmcp import FastMCP


VOL_EXE = "python3"
VOL_SCRIPT= "/app/volatility3/vol.py"
cwd= "/app/"
SYMBOLS="volatility3/volatility3/symbols/linux"

#Set name and instruction for LLM
mcp = FastMCP(name="Volitality 3 MCP Server Linux")
server_instruction = FastMCP(
    name="Volitality3",
    instructions="""
        This server provides Volatility 3 tools for ram forensic on Linux.
        Call get_version() to get Volatility 3 info.
    """,
)

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


    

#Volatility 3 tools
@mcp.tool()
async def list_available_plugins() -> str:
    """List all available Volatility plugins"""
    return await run_volatility(["-h"])

@mcp.tool()
async def get_image_info(memory_dump_path: str) -> str:

    memory_dump_path = os.path.normpath(memory_dump_path)
    if not os.path.isfile(memory_dump_path):
        return f"Error: Memory dump file not found at {memory_dump_path}"

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

    if not search_dir:
        search_dir = os.getcwd()
    
    search_dir = os.path.normpath(search_dir)
    if not os.path.isdir(search_dir):
        return f"Error: Directory not found at {search_dir}"
  
    memory_extensions = ['.raw', '.vmem', '.dmp', '.mem', '.bin', '.img', '.001', '.dump']
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

#Resource for faster lookup
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

#Get Linux Symbols
async def get_linux_symbols(memory_dump_path: str):
    """Check and get the linux symbols for Volatility"""
    banners = await run_volatility(["-f", memory_dump_path, "banners"])
    return await banners

def get_links(kernel_version: str):
    commands = usf.find_symbols(kernel_version)
    for command in commands:
        print(command)

#Run the server
if __name__ == "__main__":
    # This runs the server, we will use HTTP
    banners = asyncio.run(run_volatility(["-f", "02_working/MemLabs-Lab6/mem.avml", "banners"]))
    BANNER_PATTERN = r"(Linux version .*)"
    kernel_version = None
    for line in banners.strip().split('\n'):
        match = re.search(BANNER_PATTERN, line)
        if match:
            kernel_version = match.group(1).strip()
            break
    get_links(kernel_version)
    print(kernel_version)