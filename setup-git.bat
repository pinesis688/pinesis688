@echo off
cd /d "c:\Users\Lecoo\Desktop\pinesis688-main\pinesis688-main"
"D:\git\bin\git.exe" config user.name "SecureFx"
"D:\git\bin\git.exe" config user.email "securefx@example.com"
"D:\git\bin\git.exe" commit -m "Initial commit - SecureFx v3.0.0"
"D:\git\bin\git.exe" tag -a v3.0.0 -m "Release v3.0.0"
"D:\git\bin\git.exe" log --oneline -1
"D:\git\bin\git.exe" tag -l
pause
