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
set "MESH_SYMBOL_TEST_DIR=%TEMP%\meshagent-windows-symbol-tests-%MESH_TEST_ARCH%"
if not exist "%MESH_SYMBOL_TEST_DIR%" mkdir "%MESH_SYMBOL_TEST_DIR%"
cl /nologo /O2 /MT /Gy /Gw /Zi /std:c17 /DWIN32 /DMICROSTACK_NO_STDAFX /DMICROSTACK_NOTLS /I. /Iopenssl/include /c microstack\ILibCrypto.c /Fo:"%MESH_SYMBOL_TEST_DIR%\crypto.obj"
if errorlevel 1 exit /b %errorlevel%
cl /nologo /O2 /MT /Gy /Gw /Zi /std:c17 /I. /Iopenssl/include test\windows-symbol-tests.c /Fo:"%MESH_SYMBOL_TEST_DIR%\symbols.obj" /Fe:"%MESH_SYMBOL_TEST_DIR%\symbols.exe" /link /DEBUG /OPT:REF "%MESH_SYMBOL_TEST_DIR%\crypto.obj" dbghelp.lib ws2_32.lib iphlpapi.lib user32.lib advapi32.lib bcrypt.lib
if errorlevel 1 exit /b %errorlevel%
"%MESH_SYMBOL_TEST_DIR%\symbols.exe"
if errorlevel 1 exit /b %errorlevel%
"%MESH_SYMBOL_TEST_DIR%\symbols.exe" --offset-first
exit /b %errorlevel%
