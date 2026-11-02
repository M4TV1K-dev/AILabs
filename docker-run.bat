@echo off
chcp 65001 > nul
echo ======================================================================
echo    Host Security Auditor (Docker Runner)
echo ======================================================================
echo.
echo Сборка и запуск контейнера через Docker Compose...
echo.

docker compose up -d --build

if %errorlevel% neq 0 (
    echo.
    echo [ОШИБКА] Не удалось запустить Docker Compose. Убедитесь, что Docker Desktop запущен!
    pause
    exit /b %errorlevel%
)

echo.
echo ======================================================================
echo  ✓ Аудитор успешно запущен в контейнере!
echo  🌐 Веб-интерфейс: http://localhost:8080
echo  🔌 Связь с хостом: host.docker.internal:5000 (или :11434 для Ollama)
echo ======================================================================
echo.
pause
