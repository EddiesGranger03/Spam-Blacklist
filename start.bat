@echo off
rem ====================================================================
rem  START.BAT - nhan dup chuot file nay de chay he thong VSF Blacklist.
rem  Moi lan chay no tu lam 4 viec:
rem    1) kiem tra Docker  2) bat Postgres + Redis (du lieu duoc GIU NGUYEN)
rem    3) tat ban server cu neu dang chay  4) build lai code moi nhat roi chay
rem  => Sua code xong chi can chay lai file nay, khong can lam gi them.
rem ====================================================================
chcp 65001 >nul
cd /d "%~dp0"
title VSF Blacklist Server

echo.
echo [1/4] Kiem tra Docker Desktop...
docker info >nul 2>&1
if errorlevel 1 (
    echo.
    echo [LOI] Docker Desktop chua chay. Hay mo Docker Desktop, doi no san sang, roi chay lai file nay.
    pause
    exit /b 1
)

echo [2/4] Bat Postgres + Redis (du lieu duoc giu nguyen)...
docker compose -f deploy/docker-compose.yml up -d
if errorlevel 1 (
    echo.
    echo [LOI] Khong bat duoc Postgres/Redis. Xem thong bao o tren.
    pause
    exit /b 1
)

echo [3/4] Tat ban server cu (neu dang chay)...
powershell -NoProfile -Command "Get-Process | Where-Object { $_.Path -eq '%~dp0server.exe' } | Stop-Process -Force"

echo [4/4] Build lai code moi nhat...
go build -o server.exe ./cmd/server
if errorlevel 1 (
    echo.
    echo [LOI] Code dang bi loi - xem thong bao o tren. Server KHONG duoc khoi dong.
    echo       Sua loi roi chay lai file nay.
    pause
    exit /b 1
)

set APP_ENV=development
set HTTP_ADDR=127.0.0.1:8090
set DATABASE_URL=postgres://vsf:vsf@localhost:5433/vsf?sslmode=disable
set REDIS_ADDR=localhost:6379
set SESSION_SECRET=dev-secret-not-for-production-0123456789
set BOOTSTRAP_ADMIN_EMAIL=admin@example.com
set BOOTSTRAP_ADMIN_PASSWORD=ChangeMe-12345

echo.
echo =====================================================
echo   Server dang chay:  http://127.0.0.1:8090
echo   Trang quan tri:    http://127.0.0.1:8090/admin/login
echo   Tai khoan:         admin@example.com
echo   Mat khau:          ChangeMe-12345
echo -----------------------------------------------------
echo   De TAT server: nhan Ctrl+C trong cua so nay,
echo   hoac chay file stop.bat
echo =====================================================
echo.

rem Tu mo trinh duyet sau 4 giay (bo qua neu dat VSF_NO_BROWSER=1)
if not defined VSF_NO_BROWSER start "" cmd /c "timeout /t 4 /nobreak >nul & start http://127.0.0.1:8090/admin/login"

rem Dung ".\" de chay dung file trong thu muc nay (mot so may khong tu tim trong thu muc hien tai)
.\server.exe

echo.
echo Server da dung (ma thoat: %errorlevel%).
pause
