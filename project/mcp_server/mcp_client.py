import asyncio
from fastmcp import Client, FastMCP

server = FastMCP("Volitality3")
client = Client(server)

client = Client("mcp_server_windows.py")

async def main():
    async with client:
        # Basic server interaction
        await client.ping()
        
        # List available operations
        tools = await client.list_tools()
        resources = await client.list_resources()
        prompts = await client.list_prompts()

        print(resources)

asyncio.run(main())