FROM python:3-slim

# Volatility3_MCP - Docker-Only Memory Forensics Platform
# This project is designed to run EXCLUSIVELY in Docker containers

# Set the working directory inside the container
WORKDIR /app

# 1. Copy requirements.txt first (Good for Docker caching)
COPY requirements.txt .
COPY project .

# 2. Install all system dependencies required for compilation AND the application to run.
# This single RUN block installs tools, performs the Python installation, 
# installs dwarf2json, and then cleans up the unused build tools.
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
        # Dependencies for Pillow (The fix for the build error)
        libjpeg-dev \
        zlib1g-dev \
        libpng-dev \
        # Tools for Volatility/general compilation
        golang-go \
        build-essential \
        cmake \
        xz-utils \
        python3-dev \
        git \
        wget \
        ca-certificates && \
    \
    # Install Python dependencies from requirements.txt
    pip install --no-cache-dir -r requirements.txt && \
    \
    # Install Volatility 3 and its dev/extras dependencies
    pip install --no-cache-dir volatility3 && \
    pip install --no-cache-dir -e "volatility3[full]" && \
    \
    # Install dwarf2json
    git clone https://github.com/volatilityfoundation/dwarf2json.git && \
    cd dwarf2json && \
    go build -o /usr/local/bin/dwarf2json && \
    cd /app && \
    rm -rf dwarf2json && \
    \
    # CLEANUP: Remove the large build tools and development headers
    apt-get remove -y build-essential cmake python3-dev golang-go git \
        libjpeg-dev zlib1g-dev libpng-dev && \
    # Autoremove any orphaned dependencies and clean up apt lists to shrink the final image layer
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 3. Copy your project code (placed late to ensure fast iteration on code changes)

# Create a startup script to run both MCP servers
RUN echo '#!/bin/bash\n\
echo "Starting Volatility3 MCP Servers..."\n\
echo "Linux MCP Server starting on port 8000..."\n\
python3 /app/mcp_server/mcp_server_linux.py &\n\
LINUX_PID=$!\n\
echo "Windows MCP Server starting on port 8001..."\n\
python3 /app/mcp_server/mcp_server_windows.py &\n\
WINDOWS_PID=$!\n\
echo "Both MCP servers started successfully!"\n\
echo "Linux MCP Server (PID: $LINUX_PID) - http://localhost:8000/Linux"\n\
echo "Windows MCP Server (PID: $WINDOWS_PID) - http://localhost:8001/Windows"\n\
echo "Waiting for servers..."\n\
wait' > /app/start_servers.sh && \
chmod +x /app/start_servers.sh

# Expose both ports
EXPOSE 8000 8001

# Create volume mount point for memory dumps
VOLUME ["/app/02_working"]

CMD ["/app/start_servers.sh"]
