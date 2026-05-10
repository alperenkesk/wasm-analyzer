@echo off
REM WASM Analyzer - Build Script for Windows
REM Usage: build.bat [path-to-burpsuite_pro.jar]

setlocal

set BURP_JAR=%1

REM Auto-detect if not provided
if "%BURP_JAR%"=="" (
    if exist "%USERPROFILE%\BurpSuitePro\burpsuite_pro.jar" (
        set BURP_JAR=%USERPROFILE%\BurpSuitePro\burpsuite_pro.jar
    ) else if exist "C:\Program Files\BurpSuitePro\burpsuite_pro.jar" (
        set BURP_JAR=C:\Program Files\BurpSuitePro\burpsuite_pro.jar
    )
)

if "%BURP_JAR%"=="" (
    echo [!] Could not find burpsuite_pro.jar
    echo     Usage: build.bat C:\path\to\burpsuite_pro.jar
    echo     Or: build.bat C:\path\to\montoya-api.jar
    exit /b 1
)

echo [*] Using: %BURP_JAR%
echo [*] Compiling...

if not exist target\classes mkdir target\classes

dir /s /b src\main\java\*.java > %TEMP%\wasm_sources.txt

javac --release 17 -cp "%BURP_JAR%" -d target\classes @%TEMP%\wasm_sources.txt
if errorlevel 1 (
    echo [!] Compilation failed
    exit /b 1
)

echo [*] Packaging...
(
echo Manifest-Version: 1.0
echo Burp-Extension-Class: com.wasmanalyzer.WasmAnalyzerExtension
echo.
) > %TEMP%\WASM_MF.txt

jar cfm wasm-analyzer.jar %TEMP%\WASM_MF.txt -C target\classes com\

echo.
echo [OK] Built: wasm-analyzer.jar
echo Load in Burp: Extensions -^> Add -^> Java -^> select wasm-analyzer.jar
