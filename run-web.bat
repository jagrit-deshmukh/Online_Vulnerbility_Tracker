@echo off
setlocal

set VULNTRACKER_WEB_PORT=8080

java --add-modules jdk.httpserver -cp "target\classes;%USERPROFILE%\.m2\repository\com\mysql\mysql-connector-j\9.0.0\mysql-connector-j-9.0.0.jar" vulntracker.Main web