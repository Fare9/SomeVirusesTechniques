

SET ASSEMBLER="C:\Program Files\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.12.25827\bin\Hostx86\x86\ml.exe"
SET LINKER="C:\Program Files\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.12.25827\bin\Hostx86\x86\link.exe"

@echo off

REM le pasamos los siguientes parametros.
REM %1 $file_path
REM %2 $file_base_name


if not exist rsrc.rc goto over1
\masm32\bin\rc /v rsrc.rc
\masm32\bin\cvtres /machine:ix86 rsrc.res
 :over1
 
if exist %1\%2.obj del %1\%2.obj
if exist %1\%2.exe del %1\%2.exe

%ASSEMBLER% /Fo %1/%2.obj /c /coff %1/%2.asm 
if errorlevel 1 goto errasm

if not exist %1/rsrc.obj goto nores

%LINKER% /OUT:%1/%2.exe /DYNAMICBASE /NXCOMPAT /SUBSYSTEM:CONSOLE /OPT:REF /VERBOSE /MERGE:.data=.text %1/%2.obj %1/rsrc.res /OUT %2
 if errorlevel 1 goto errlink

REM dir %1.*
goto TheEnd

:nores
 \dasm\bin\link.exe /OUT:%1/%2.exe /DYNAMICBASE /NXCOMPAT /SUBSYSTEM:CONSOLE /OPT:REF /VERBOSE /MERGE:.data=.text %1/%2.obj 
 if errorlevel 1 goto errlink

REM dir %1.*
goto TheEnd

:errlink
 echo _
echo Link error
goto TheEnd

:errasm
 echo _
echo Assembly Error
goto TheEnd

:TheEnd
REM if exist %1\%2.obj del %1\%2.obj