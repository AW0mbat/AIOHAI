Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\AIOHAI\desktop"
WshShell.Run "node_modules\.bin\electron.cmd dist/main/main.js", 0, False