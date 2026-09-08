@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%\..\..") do set "ROOT=%%~fI"

cd /d "%ROOT%" || (
  echo ERROR: failed to switch to project root: %ROOT%
  exit /b 10
)
set "CONFIG=%~1"
set "TARGET=%~2"
if "%CONFIG%"=="" set "CONFIG=release"
if "%TARGET%"=="" set "TARGET=standalone"

if /I "%CONFIG%"=="debug" (
  set "PRESET=windows-debug"
  set "CMAKE_CONFIG=Debug"
  set "SUFFIX=-debug"
) else if /I "%CONFIG%"=="release" (
  set "PRESET=windows-release"
  set "CMAKE_CONFIG=Release"
  set "SUFFIX="
) else (
  echo ERROR: configuration must be debug or release.
  exit /b 2
)

if defined QT_ROOT (
  set "PATH=%QT_ROOT%\bin;%PATH%"
  if defined CMAKE_PREFIX_PATH (
    set "CMAKE_PREFIX_PATH=%QT_ROOT%;%CMAKE_PREFIX_PATH%"
  ) else (
    set "CMAKE_PREFIX_PATH=%QT_ROOT%"
  )
)

where cmake >nul 2>nul || (echo ERROR: cmake was not found in PATH. & exit /b 3)
where windeployqt >nul 2>nul || (
  echo ERROR: windeployqt was not found.
  echo Install Qt 6.2+ for MSVC x64 or set QT_ROOT to the Qt kit directory, e.g. C:\Qt\6.8.3\msvc2022_64
  exit /b 4
)

set "BUILD=%ROOT%\build\windows\%PRESET%"
set "STAGE=%ROOT%\out\windows\%CONFIG%\standalone"
set "PACKAGES=%ROOT%\out\packages"

if not exist "%PACKAGES%" mkdir "%PACKAGES%"

echo === Configure %PRESET% ===
cmake --preset %PRESET%
if errorlevel 1 exit /b %errorlevel%

echo === Build %CMAKE_CONFIG% ===
cmake --build --preset %PRESET% --parallel
if errorlevel 1 exit /b %errorlevel%

echo === Tests %CMAKE_CONFIG% ===
ctest --preset %PRESET%
if errorlevel 1 exit /b %errorlevel%

echo === Stage standalone ===
if exist "%STAGE%" rmdir /s /q "%STAGE%"
cmake --install "%BUILD%" --config %CMAKE_CONFIG% --prefix "%STAGE%"
if errorlevel 1 exit /b %errorlevel%

windeployqt --%CONFIG% --no-translations --compiler-runtime --dir "%STAGE%" "%STAGE%\NativeDNS.exe"
if errorlevel 1 exit /b %errorlevel%

if not exist "%STAGE%\NativeDNS.exe" (echo ERROR: NativeDNS.exe missing after staging. & exit /b 5)
if not exist "%STAGE%\NativeDNSCoreHost.exe" (echo ERROR: NativeDNSCoreHost.exe missing after staging. & exit /b 5)

echo Standalone ready: %STAGE%

if /I "%TARGET%"=="standalone" goto :done
if /I "%TARGET%"=="portable" goto :portable
if /I "%TARGET%"=="installer" goto :installer
if /I "%TARGET%"=="all" goto :portable_then_installer

echo ERROR: target must be standalone, portable, installer or all.
exit /b 2

:portable_then_installer
call :make_portable || exit /b !errorlevel!
goto :installer

:portable
call :make_portable || exit /b !errorlevel!
goto :done

:installer
call :make_installer || exit /b !errorlevel!
goto :done

:make_portable
set "ZIP=%PACKAGES%\NativeDNS-0.2.0-windows-x64%SUFFIX%-portable.zip"
if exist "%ZIP%" del /q "%ZIP%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%STAGE%\*' -DestinationPath '%ZIP%' -CompressionLevel Optimal"
if errorlevel 1 exit /b %errorlevel%
echo Portable ZIP ready: %ZIP%
exit /b 0

:make_installer
set "ISCC=%INNO_SETUP_ISCC%"
if "%ISCC%"=="" if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if "%ISCC%"=="" if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if "%ISCC%"=="" (
  echo ERROR: Inno Setup 6 ISCC.exe was not found.
  echo Set INNO_SETUP_ISCC to the full ISCC.exe path.
  exit /b 6
)
"%ISCC%" /DStageDir="%STAGE%" /DOutputDir="%PACKAGES%" /DConfiguration="%CMAKE_CONFIG%" "%ROOT%\packaging\NativeDNS.iss"
if errorlevel 1 exit /b %errorlevel%
echo Installer ready in: %PACKAGES%
exit /b 0

:done
echo === NativeDNS Windows %CONFIG% / %TARGET% completed ===
exit /b 0
