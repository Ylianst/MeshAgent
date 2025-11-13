@echo off
REM Clean Windows build artifacts
REM Navigate to repository root (script is in scripts\windows, repo is two levels up)
cd /d "%~dp0..\.."

del /s /q Debug
rmdir /s /q Debug
del /s /q Release
rmdir /s /q Release
del /s /q .vs
rmdir /s /q .vs
del /q MeshAgent.sdf
