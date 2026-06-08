@echo off
setlocal
set "ROOT=%~dp0"
"%ROOT%FinalCombatLocalLauncher.exe"
echo.
echo Launcher exited with code %ERRORLEVEL%.
pause
