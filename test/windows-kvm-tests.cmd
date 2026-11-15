@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%i\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
)
if errorlevel 1 exit /b %errorlevel%
cd /d "%~dp0.."
set "MESH_TEST_ARCH=%VSCMD_ARG_TGT_ARCH%"
if "%MESH_TEST_ARCH%"=="" set "MESH_TEST_ARCH=x64"
if not exist "%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%" mkdir "%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File lib-jpeg-turbo\windows\build.ps1 -Architecture %MESH_TEST_ARCH%
if errorlevel 1 exit /b %errorlevel%
cl /nologo /O2 /MT /Gy /Gw /EHsc /std:c++17 /DMESH_WINDOWS_TURBOJPEG /DWIN32 /DMICROSTACK_NO_STDAFX /I. /Imeshservice /Iopenssl/include test\windows-kvm-tests.cpp /Fo:"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\capture.obj" /Fe:"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\capture.exe" /link /OPT:REF .build\windows-jpeg\%VCToolsVersion%\%MESH_TEST_ARCH%\Release\jpeg-static.lib gdiplus.lib ole32.lib gdi32.lib user32.lib ws2_32.lib
if errorlevel 1 exit /b %errorlevel%
"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\capture.exe"
if errorlevel 1 exit /b %errorlevel%
cl /nologo /O2 /Gy /Gw /std:c17 /DWIN32 /DMICROSTACK_NO_STDAFX /I. /Iopenssl/include test\windows-kvm-input-tests.c /Fo:"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\input.obj" /Fe:"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\input.exe" /link /OPT:REF gdiplus.lib ole32.lib gdi32.lib user32.lib ws2_32.lib
if errorlevel 1 exit /b %errorlevel%
"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\input.exe"
if errorlevel 1 exit /b %errorlevel%
cl /nologo /O2 /Gy /Gw /EHsc /std:c++17 /DWIN32 /DMICROSTACK_NO_STDAFX /I. test\windows-desktop-duplication-tests.cpp /Fo:"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\duplication.obj" /Fe:"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\duplication.exe" /link /OPT:REF user32.lib gdi32.lib
if errorlevel 1 exit /b %errorlevel%
"%TEMP%\meshagent-windows-kvm-tests-%MESH_TEST_ARCH%\duplication.exe"
