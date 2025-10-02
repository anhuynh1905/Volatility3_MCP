import os
import sys
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import asyncio
from fastmcp import FastMCP


VOL_EXE = "python3"
VOL_SCRIPT= "/app/volatility3/vol.py"
cwd= "/app/02_working"

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


#Run the server
if __name__ == "__main__":
    # This runs the server, defaulting to STDIO transport
    mcp.run()