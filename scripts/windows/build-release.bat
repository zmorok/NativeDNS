@echo off
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=all"
call "%~dp0build-windows.bat" release %TARGET% %~2
exit /b %errorlevel%
