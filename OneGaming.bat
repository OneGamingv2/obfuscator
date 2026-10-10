@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title OneGaming Obfuscation
set "REPO_URL=https://github.com/OneGamingv2/obfuscator.git"
set "BRANCH=main"
set "SLN=OneGamingOBFUSCATION\OneGamingOBFUSCATION.sln"
set "EXE=OneGamingOBFUSCATION\bin\Release\net8.0-windows\win-x64\OneGamingOBFUSCATION.exe"

if /i "%~1"=="sync" goto cli_sync
if /i "%~1"=="build" goto cli_build
if /i "%~1"=="rebuild" goto cli_rebuild
if /i "%~1"=="run" goto cli_run
if /i "%~1"=="menu" goto menu
if not "%~1"=="" goto usage

call :require_git
if errorlevel 1 goto fail
if not exist ".git\" (
    call :clone_here
    if errorlevel 1 goto fail
)
call :sync
if errorlevel 1 goto fail
goto menu

:usage
echo.
echo Usage:
echo   OneGaming.bat           Sync from GitHub, then open the menu
echo   OneGaming.bat sync      Download the newest code and restore missing files
echo   OneGaming.bat build     Build the Release program
echo   OneGaming.bat rebuild   Clean, then build
echo   OneGaming.bat run       Start the program
echo   OneGaming.bat menu      Open the menu without syncing
echo.
exit /b 1

:cli_sync
call :require_git
if errorlevel 1 exit /b 1
if not exist ".git\" (
    call :clone_here
    if errorlevel 1 exit /b 1
)
call :sync
exit /b %ERRORLEVEL%

:cli_build
call :require_dotnet
if errorlevel 1 exit /b 1
call :build
exit /b %ERRORLEVEL%

:cli_rebuild
call :require_dotnet
if errorlevel 1 exit /b 1
call :rebuild
exit /b %ERRORLEVEL%

:cli_run
call :run
exit /b %ERRORLEVEL%

:menu
cls
echo ============================================================
echo   OneGaming Obfuscation
echo   GitHub sync and builder
echo ============================================================
echo   Repo    %REPO_URL%
echo   Branch  %BRANCH%
call :print_head
echo ============================================================
echo   1  Sync newest code and restore missing files
echo   2  Build Release
echo   3  Clean, then build
echo   4  Run the program
echo   5  Build, then run
echo   6  Show local changes
echo   7  Open this folder
echo   0  Exit
echo ============================================================
choice /c 12345670 /n /m "Select: "
if errorlevel 8 goto done
if errorlevel 7 goto open_folder
if errorlevel 6 goto show_status
if errorlevel 5 goto build_and_run
if errorlevel 4 goto run_only
if errorlevel 3 goto rebuild_only
if errorlevel 2 goto build_only
if errorlevel 1 goto sync_only
goto menu

:sync_only
echo.
call :sync
echo.
pause
goto menu

:build_only
echo.
call :require_dotnet
if errorlevel 1 (
    pause
    goto menu
)
call :build
echo.
pause
goto menu

:rebuild_only
echo.
call :require_dotnet
if errorlevel 1 (
    pause
    goto menu
)
call :rebuild
echo.
pause
goto menu

:run_only
echo.
call :run
echo.
pause
goto menu

:build_and_run
echo.
call :require_dotnet
if errorlevel 1 (
    pause
    goto menu
)
call :build
if errorlevel 1 (
    echo Build failed.
    pause
    goto menu
)
call :run
echo.
pause
goto menu

:show_status
echo.
git status -sb
echo.
git log -5 --oneline
echo.
pause
goto menu

:open_folder
start "" "%cd%"
goto menu

:done
exit /b 0

:fail
echo.
pause
exit /b 1

:require_git
where git >nul 2>&1
if errorlevel 1 (
    echo Git is not installed.
    echo Install it from https://git-scm.com/download/win
    echo Then run this file again.
    exit /b 1
)
exit /b 0

:require_dotnet
where dotnet >nul 2>&1
if errorlevel 1 (
    echo The .NET 8 SDK is not installed.
    echo Install it from https://dotnet.microsoft.com/download/dotnet/8.0
    exit /b 1
)
exit /b 0

:clone_here
echo This folder is not the project yet. Downloading it...
set "STAGE=%TEMP%\OneGamingObfuscator"
if exist "%STAGE%\" rmdir /s /q "%STAGE%"
git clone --branch %BRANCH% --single-branch "%REPO_URL%" "%STAGE%"
if errorlevel 1 (
    echo Download failed. Check the internet connection and the GitHub address.
    exit /b 1
)
robocopy "%STAGE%" "%cd%" /E /NFL /NDL /NJH /NJS /nc /ns /np
set "RC=%ERRORLEVEL%"
rmdir /s /q "%STAGE%"
if %RC% GEQ 8 (
    echo The downloaded files could not be copied into this folder.
    exit /b 1
)
echo Download finished.
exit /b 0

:sync
echo Syncing %BRANCH% from GitHub...
git fetch origin %BRANCH%
if errorlevel 1 (
    echo Could not reach GitHub.
    exit /b 1
)
git checkout -f -B %BRANCH% origin/%BRANCH%
if errorlevel 1 (
    echo Could not replace local files with the GitHub copy.
    exit /b 1
)
echo.
echo This folder matches GitHub. Missing and changed tracked files were replaced.
call :print_head
exit /b 0

:print_head
git log -1 --oneline 2>nul
exit /b 0

:build
echo Building Release...
dotnet build "%SLN%" -c Release --nologo
exit /b %ERRORLEVEL%

:rebuild
echo Cleaning Release...
dotnet clean "%SLN%" -c Release --nologo
if errorlevel 1 exit /b 1
call :build
exit /b %ERRORLEVEL%

:run
if not exist "%EXE%" (
    echo The program is not built yet. Choose Build first.
    exit /b 1
)
echo Starting %EXE%
start "" "%EXE%"
exit /b 0
