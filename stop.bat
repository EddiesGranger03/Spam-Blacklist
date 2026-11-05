@echo off
rem ====================================================================
rem  STOP.BAT - tat server VSF.
rem  Postgres/Redis van chay de GIU DU LIEU (tat chung cung an toan:
rem  docker compose -f deploy/docker-compose.yml stop).
rem  CANH BAO: KHONG BAO GIO dung "docker compose down -v" - no XOA SACH du lieu.
rem ====================================================================
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -Command "$p = Get-Process | Where-Object { $_.Path -eq '%~dp0server.exe' }; if ($p) { $p | Stop-Process -Force; 'Da tat server VSF.' } else { 'Server VSF khong chay.' }"
echo.
pause
