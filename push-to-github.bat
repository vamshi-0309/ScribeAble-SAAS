@echo off
echo ==============================================
echo Pushing ScribeAble to GitHub...
echo ==============================================
cd /d "c:\Users\mvams\OneDrive\Desktop\chinnu project"

:: Check if git is initialized
if not exist .git (
    echo Initializing Git repository...
    git init
    git remote add origin https://github.com/vamshi-0309/ScribeAble-SAAS
) else (
    echo Git already initialized. Checking remote...
    git remote remove origin 2>nul
    git remote add origin https://github.com/vamshi-0309/ScribeAble-SAAS
)

echo.
echo Staging files...
git add .

echo.
echo Committing files...
git commit -m "Initialize ScribeAble project with local Node server and fixed login/signup flow"

echo.
echo Setting branch to main...
git branch -M main

echo.
echo Pushing code to GitHub (you may be prompted for authentication)...
git push -u origin main

echo.
echo Done! Please check https://github.com/vamshi-0309/ScribeAble-SAAS
pause
