@echo off
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=all"
call "%~dp0build-windows.bat" debug %TARGET% %~2
exit /b %errorlevel%
