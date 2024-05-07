@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:functionObfuscated-v3.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj