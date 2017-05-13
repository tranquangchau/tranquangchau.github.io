@echo off
git pull
git status
git add --all
SET /P _inputname= Please enter an comment commit: 
IF "%_inputname%"=="OMG" "%_inputname%"="auto" 
git commit -a -m "%_inputname%"
git push
pause
