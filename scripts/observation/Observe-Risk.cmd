@echo off
setlocal
if "%~1"=="" (
    python -X utf8 "%~dp0observe.py" --watch-seconds 5 --open
) else (
    python -X utf8 "%~dp0observe.py" %*
)
exit /b %errorlevel%
