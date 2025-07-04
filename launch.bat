@echo off
cd /d "%~dp0"
powershell -WindowStyle Hidden -Command "Start-Process python 'main.py' -WindowStyle Hidden -Verb RunAs"

