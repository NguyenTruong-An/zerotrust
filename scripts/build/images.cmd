@echo off
python -X utf8 "%~dp0images.py" %*
exit /b %ERRORLEVEL%
