@echo off
REM Volatility3 MCP Server Management Script for Windows
REM Docker-Only Memory Forensics Platform

set CONTAINER_NAME=volatility3-mcp-servers
set IMAGE_NAME=volatility3-mcp

echo 🐳 Volatility3_MCP - Docker-Only Platform
echo ==========================================

if "%1"=="build" goto build
if "%1"=="start" goto start
if "%1"=="stop" goto stop
if "%1"=="restart" goto restart
if "%1"=="logs" goto logs
if "%1"=="shell" goto shell
if "%1"=="status" goto status
if "%1"=="clean" goto clean
goto help

:build
echo Building Volatility3 MCP Docker image...
docker build -t %IMAGE_NAME% .
goto end

:start
echo Starting Volatility3 MCP servers...
docker-compose up -d
echo Servers started!
echo Linux MCP Server: http://localhost:8000/Linux
echo Windows MCP Server: http://localhost:8001/Windows
goto end

:stop
echo Stopping Volatility3 MCP servers...
docker-compose down
goto end

:restart
echo Restarting Volatility3 MCP servers...
docker-compose restart
goto end

:logs
echo Showing server logs...
docker-compose logs -f
goto end

:shell
echo Opening shell in container...
docker exec -it %CONTAINER_NAME% /bin/bash
goto end

:status
echo Checking server status...
docker-compose ps
echo.
echo Health check:
curl -s http://localhost:8000/Linux >nul 2>&1 && echo ✅ Linux MCP Server: Running || echo ❌ Linux MCP Server: Not responding
curl -s http://localhost:8001/Windows >nul 2>&1 && echo ✅ Windows MCP Server: Running || echo ❌ Windows MCP Server: Not responding
goto end

:clean
echo Cleaning up containers and images...
docker-compose down --rmi all --volumes
goto end

:help
echo Volatility3 MCP Server Management
echo Usage: %0 {build^|start^|stop^|restart^|logs^|shell^|status^|clean}
echo.
echo Commands:
echo   build    - Build the Docker image
echo   start    - Start both MCP servers
echo   stop     - Stop the servers
echo   restart  - Restart the servers
echo   logs     - Show server logs
echo   shell    - Open bash shell in container
echo   status   - Check if servers are running
echo   clean    - Remove containers and images

:end