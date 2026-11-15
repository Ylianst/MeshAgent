@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%i\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
)
if errorlevel 1 exit /b %errorlevel%
cd /d "%~dp0.."
set "MESH_CRYPTO_ARCH=%VSCMD_ARG_TGT_ARCH%"
if "%MESH_CRYPTO_ARCH%"=="" set "MESH_CRYPTO_ARCH=x64"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File openssl\windows\build.ps1 -Architecture %MESH_CRYPTO_ARCH%
if errorlevel 1 exit /b %errorlevel%
set "MESH_CRYPTO_INSTALL=.build\windows-openssl\%VCToolsVersion%\%MESH_CRYPTO_ARCH%\Release\install"
set "MESH_CRYPTO_TEST_DIR=%TEMP%\meshagent-windows-crypto-tests-%MESH_CRYPTO_ARCH%"
if not exist "%MESH_CRYPTO_TEST_DIR%" mkdir "%MESH_CRYPTO_TEST_DIR%"
cl /nologo /O2 /MT /EHsc /I"%MESH_CRYPTO_INSTALL%\include" test\windows-crypto-tests.cpp /Fo:"%MESH_CRYPTO_TEST_DIR%\crypto.obj" /Fe:"%MESH_CRYPTO_TEST_DIR%\crypto.exe" /link "%MESH_CRYPTO_INSTALL%\lib\libcrypto.lib" crypt32.lib bcrypt.lib advapi32.lib user32.lib ws2_32.lib psapi.lib
if errorlevel 1 exit /b %errorlevel%
cl /nologo /O2 /MT /EHsc /I"%MESH_CRYPTO_INSTALL%\include" test\windows-crypto-tls-tests.cpp /Fo:"%MESH_CRYPTO_TEST_DIR%\tls.obj" /Fe:"%MESH_CRYPTO_TEST_DIR%\tls.exe" /link "%MESH_CRYPTO_INSTALL%\lib\libssl.lib" "%MESH_CRYPTO_INSTALL%\lib\libcrypto.lib" crypt32.lib bcrypt.lib advapi32.lib user32.lib ws2_32.lib psapi.lib
if errorlevel 1 exit /b %errorlevel%
cl /nologo /O2 /MT /EHsc /I"%MESH_CRYPTO_INSTALL%\include" test\windows-crypto-identity-tests.cpp /Fo:"%MESH_CRYPTO_TEST_DIR%\identity.obj" /Fe:"%MESH_CRYPTO_TEST_DIR%\identity.exe" /link "%MESH_CRYPTO_INSTALL%\lib\libssl.lib" "%MESH_CRYPTO_INSTALL%\lib\libcrypto.lib" crypt32.lib bcrypt.lib advapi32.lib user32.lib ws2_32.lib psapi.lib
if errorlevel 1 exit /b %errorlevel%
"%MESH_CRYPTO_TEST_DIR%\crypto.exe"
if errorlevel 1 exit /b %errorlevel%
"%MESH_CRYPTO_TEST_DIR%\tls.exe"
if errorlevel 1 exit /b %errorlevel%
"%MESH_CRYPTO_TEST_DIR%\identity.exe"
if errorlevel 1 exit /b %errorlevel%
rem Restrict CPU features only in this test process tree; never the Agent service.
set "OPENSSL_ia32cap=0:0"
"%MESH_CRYPTO_TEST_DIR%\crypto.exe"
if errorlevel 1 exit /b %errorlevel%
"%MESH_CRYPTO_TEST_DIR%\tls.exe"
exit /b %errorlevel%
