@echo off
chcp 65001 > nul
echo ======================================================================
echo    Host Security Auditor (Go + Local LLM SOC Pipeline)
echo ======================================================================
echo.

:: Закрываем старый зависший процесс auditor.exe, если он уже был запущен
taskkill /F /IM auditor.exe >nul 2>&1

echo Запуск веб-сервера аудитора на http://localhost:8080 ...
echo.

if exist auditor.exe (
    .\auditor.exe
) else (
    go run .\cmd\auditor
)

pause
