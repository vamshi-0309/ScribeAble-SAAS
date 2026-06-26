@echo off
echo ==============================================
echo Pushing ScribeAble to GitHub...
echo ==============================================
cd /d "c:\Users\mvams\OneDrive\Desktop\chinnu project"

:: Ensure remote is set
git remote remove origin 2>nul
git remote add origin https://github.com/vamshi-0309/ScribeAble-SAAS

echo.
echo Staging all files...
git add .

echo.
echo Committing files...
git commit -m "Fix Vercel 500 error: add api/server.js, vercel.json routing, CDN WASM fix, .env support"

echo.
echo Setting branch to main...
git branch -M main

echo.
echo Pushing to GitHub...
git push -u origin main

echo.
echo Done! Check https://github.com/vamshi-0309/ScribeAble-SAAS
pause
