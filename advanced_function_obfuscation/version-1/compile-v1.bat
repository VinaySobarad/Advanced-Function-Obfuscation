@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /TcfunctionObfuscated-v1.cpp /link /OUT:functionObfuscated-v1.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj