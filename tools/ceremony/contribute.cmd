@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul || (echo Install Node.js 24 or newer, then rerun. & exit /b 1)
where npm >nul 2>nul || (echo Install npm with Node.js, then rerun. & exit /b 1)
where git >nul 2>nul || (echo Install Git, then rerun. & exit /b 1)
node -e "if (!(Number(process.versions.node.split('.')[0]) >= 24)) { console.error('Node.js 24 or newer is required'); process.exit(1); }"
if errorlevel 1 exit /b 1
if not exist assignment.json (echo Use the participant package supplied for your turn. & exit /b 1)
call npm ci --ignore-scripts --no-audit --no-fund
if errorlevel 1 exit /b 1
node ceremony.mjs contribute --package . --out submission %*
exit /b %errorlevel%
