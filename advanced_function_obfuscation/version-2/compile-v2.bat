@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /TcfunctionObfuscated-v2.cpp /link /OUT:functionObfuscated-v2.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj