@echo off
chcp 65001 >nul
py -3 "%USERPROFILE%\.claude\tools\review_scan.py" %*
