@echo off
setlocal
reg add HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v "Start" /t REG_DWORD /d 3 /f > nul
