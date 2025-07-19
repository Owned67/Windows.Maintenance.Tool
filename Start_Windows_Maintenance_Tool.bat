@echo off
:: Batchfile to always run PowerShell script as administrator, keep window open

:: Find script location
set SCRIPT=%~dp0Windows_Maintenance_Tool_French.ps1

net file 1>nul 2>nul && goto :Main || powershell -ex unrestricted -Command "Start-Process -Verb RunAs -NoExit -FilePath '%comspec%' -ArgumentList '/c %~fnx0 %*'"
goto :eof

:Main
:: Start PowerShell as administrator with -NoExit, regardless of user's execution policy
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process PowerShell -ArgumentList '-NoExit -File \"%SCRIPT%\"'"
