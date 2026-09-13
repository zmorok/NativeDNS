@echo off
set "CFG=%~1"
if "%CFG%"=="" set "CFG=release"
call "%~dp0build-windows.bat" %CFG% all %~2
exit /b %errorlevel%
