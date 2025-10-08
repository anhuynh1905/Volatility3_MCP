import asyncio
import re
import subprocess 
import shlex
import os
from utils import ubuntu_symbols_finder as usf

BANNER_PATH = "/app/02_working/volatility/banners.txt"

VOL_EXE = "python3"
VOL_SCRIPT= "/app/volatility3/vol.py"
cwd= "/app/Ubuntu_symbols"
DISK_PATH="/app/02_working/MemLabs-Lab6/mem.avml"
BANNER_PATTERN = r"0x[0-9a-f]+\s+(Linux version .*)"



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


async def get_symbols(commands: list[str]) -> bool:
    for command in commands:
        needs_shell = "|" in command or ">" in command
        #print(f"\n--- Executing: {command} (shell={needs_shell}) ---")

        if not needs_shell:
            args = shlex.split(command)
        else:
            args = ["sh", "-c", command] 
            
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                #print(f"FAILED (Code {process.returncode})")
                #print(f"Error Output:\n{stderr.decode('utf-8', errors='replace')}")
                return False 
            

        except FileNotFoundError:
            #print(f"FAILED: Executable not found for command starting with '{args[0]}'")
            return False
        except Exception as e:
            #print(f"FAILED: An unexpected error occurred: {e}")
            return False

    
async def main():
    output = await run_volatility(["-f", DISK_PATH, "banners"])
    banners = None

    for line in output.splitlines():
        match = re.search(BANNER_PATTERN, line)

        if match:
            banners = match.group(1).strip()

    print(await get_symbols(usf.find_symbols(banners)))

if __name__ == "__main__":
    asyncio.run(main())