@echo off
set VULNTRACKER_WEB_PORT=8080
java --add-modules jdk.httpserver -cp target\classes vulntracker.Main web
