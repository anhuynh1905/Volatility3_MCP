#!/bin/bash

# Volatility3 MCP Server Management Script
# Docker-Only Memory Forensics Platform

CONTAINER_NAME="volatility3-mcp-servers"
IMAGE_NAME="volatility3-mcp"

echo "🐳 Volatility3_MCP - Docker-Only Platform"
echo "=========================================="

case "$1" in
    "build")
        echo "Building Volatility3 MCP Docker image..."
        docker build -t $IMAGE_NAME .
        ;;
    "start")
        echo "Starting Volatility3 MCP servers..."
        docker-compose up -d
        echo "Servers started!"
        echo "Linux MCP Server: http://localhost:8000/Linux"
        echo "Windows MCP Server: http://localhost:8001/Windows"
        ;;
    "stop")
        echo "Stopping Volatility3 MCP servers..."
        docker-compose down
        ;;
    "restart")
        echo "Restarting Volatility3 MCP servers..."
        docker-compose restart
        ;;
    "logs")
        echo "Showing server logs..."
        docker-compose logs -f
        ;;
    "shell")
        echo "Opening shell in container..."
        docker exec -it $CONTAINER_NAME /bin/bash
        ;;
    "status")
        echo "Checking server status..."
        docker-compose ps
        echo ""
        echo "Health check:"
        curl -s http://localhost:8000/Linux > /dev/null && echo "✅ Linux MCP Server: Running" || echo "❌ Linux MCP Server: Not responding"
        curl -s http://localhost:8001/Windows > /dev/null && echo "✅ Windows MCP Server: Running" || echo "❌ Windows MCP Server: Not responding"
        ;;
    "clean")
        echo "Cleaning up containers and images..."
        docker-compose down --rmi all --volumes
        ;;
    *)
        echo "Volatility3 MCP Server Management"
        echo "Usage: $0 {build|start|stop|restart|logs|shell|status|clean}"
        echo ""
        echo "Commands:"
        echo "  build    - Build the Docker image"
        echo "  start    - Start both MCP servers"
        echo "  stop     - Stop the servers"
        echo "  restart  - Restart the servers"
        echo "  logs     - Show server logs"
        echo "  shell    - Open bash shell in container"
        echo "  status   - Check if servers are running"
        echo "  clean    - Remove containers and images"
        exit 1
        ;;
esac