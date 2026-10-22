@echo off
setlocal
set "DEMO_ROOT=%~dp0..\.."
set "COMPOSE_FILE=%DEMO_ROOT%\compose.yaml"
if "%~1"=="start" goto start
if "%~1"=="stop" goto stop
if "%~1"=="build" goto build
if "%~1"=="logs" goto logs
docker compose --project-name zerotrust-demo --project-directory "%DEMO_ROOT%" ps
exit /b %errorlevel%
:start
docker compose --project-name zerotrust-demo --project-directory "%DEMO_ROOT%" up -d --wait --wait-timeout 240
exit /b %errorlevel%
:stop
docker compose --project-name zerotrust-demo --project-directory "%DEMO_ROOT%" stop --timeout 35
exit /b %errorlevel%
:build
docker compose --project-name zerotrust-demo --project-directory "%DEMO_ROOT%" build %2
exit /b %errorlevel%
:logs
docker compose --project-name zerotrust-demo --project-directory "%DEMO_ROOT%" logs --tail 100 %2
exit /b %errorlevel%
