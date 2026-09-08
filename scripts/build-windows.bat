@echo off
call "%~dp0windows\build-windows.bat" %*
exit /b %errorlevel%
