@echo off
setlocal
if "%VULNTRACKER_DB_URL%"=="" set VULNTRACKER_DB_URL=jdbc:mysql://localhost:3306/vulntracker?useSSL=false&serverTimezone=UTC
if "%VULNTRACKER_DB_USER%"=="" set VULNTRACKER_DB_USER=root
if "%VULNTRACKER_DB_PASSWORD%"=="" (
  echo Set VULNTRACKER_DB_PASSWORD before running the application.
  exit /b 1
)
call mvn -q package
if errorlevel 1 exit /b 1
java -cp "target/classes;%USERPROFILE%\.m2\repository\com\mysql\mysql-connector-j\9.0.0\mysql-connector-j-9.0.0.jar" vulntracker.Main
