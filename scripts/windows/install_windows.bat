@echo off
:: ╔══════════════════════════════════════════════════════════════════╗
:: ║  DIS-CORE — Windows Installer                                  ║
:: ║  IrsanAI Stack · github.com/IrsanAI/IrsanAI-dis-core           ║
:: ╚══════════════════════════════════════════════════════════════════╝
:: Double-click this file to install DIS on Windows

title DIS-CORE Windows Installer

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║  DIS - Device Intelligence System              ║
echo  ║  Windows Installer                             ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
  echo [!] Node.js nicht gefunden!
  echo.
  echo  Bitte installieren von: https://nodejs.org
  echo  LTS Version empfohlen.
  echo.
  start https://nodejs.org
  pause
  exit
)

echo [OK] Node.js gefunden: 
node --version

:: Check Git
git --version >nul 2>&1
if errorlevel 1 (
  echo [!] Git nicht gefunden!
  echo.
  echo  Bitte installieren von: https://git-scm.com
  start https://git-scm.com
  pause
  exit
)

echo [OK] Git gefunden:
git --version

:: Install dependencies
echo.
echo [1/3] NPM Packages installieren...
npm install

:: Build
echo.
echo [2/3] Dashboard bauen...
npm run build

:: Done
echo.
echo [3/3] Fertig!
echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║  ✅  DIS-CORE bereit!                          ║
echo  ║                                                ║
echo  ║  Server starten: node server.js               ║
echo  ║  Browser öffnen: http://localhost:3001         ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: Ask to start server
set /p START="Server jetzt starten? (j/n): "
if /i "%START%"=="j" (
  echo Starte DIS-CORE Server...
  start "" http://localhost:3001
  node server.js
)

pause
