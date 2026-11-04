@echo off
python -X utf8 "%~dp0zt.py" %*
exit /b %ERRORLEVEL%
