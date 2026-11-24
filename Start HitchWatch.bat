@echo off
rem HitchWatch (see README.md): records 60 s of kernel trace + PresentMon frame times while you play,
rem then writes captures\<time>\REPORT.md naming what was busy during each hitch. One UAC prompt (the kernel trace
rem needs admin). Start it while the game runs (or before: it waits for the game). Extra arguments are passed on,
rem e.g. "Start HitchWatch.bat" --seconds 90 --delay 15. Never starts, stops or edits the game.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "try { $a = '%*'; if ($a) { Start-Process -FilePath '%~f0' -ArgumentList $a -Verb RunAs -ErrorAction Stop } else { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop }; exit 0 } catch { exit 1 }"
  if not errorlevel 1 exit /b
  echo UAC was declined: HitchWatch needs admin for the kernel trace. Nothing was recorded.
  pause
  exit /b 1
)
title HitchWatch
cd /d "%~dp0"
python -I -X utf8 "%~dp0hitchwatch.py" record %*
echo.
pause
