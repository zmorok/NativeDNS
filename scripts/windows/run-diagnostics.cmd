@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0diagnose-service.ps1" -PackageDirectory "%~dp0." %*
set "DIAGNOSTIC_RESULT=%ERRORLEVEL%"
echo.
if not "%DIAGNOSTIC_RESULT%"=="0" echo Diagnostics did not finish. Please keep the error text shown above.
echo Diagnostic output is saved in the logs folder next to NativeDNS.exe.
pause
exit /b %DIAGNOSTIC_RESULT%
