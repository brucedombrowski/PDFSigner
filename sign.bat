@echo off
REM PdfSigner - Drag and drop a PDF onto this file to sign it
REM Uses the Windows GUI certificate picker

if "%~1"=="" (
    echo Usage: Drag a PDF file onto this batch file to sign it.
    echo Or run: sign.bat document.pdf
    pause
    exit /b 1
)

"%~dp0PdfSigner.exe" "%~1" --gui
pause
