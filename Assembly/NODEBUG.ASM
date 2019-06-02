;
;		Métodos y técnicas antidebugging en assembly
;		estas serán técnicas genéricas
;
;	Paper tuts4you
;	https://tuts4you.com/e107_plugins/download/download.php?action=view&id=1919

.486
.model flat, stdcall
option casemap:none
assume fs:nothing ; necesario para que no tome cualquier valor de fs

include \MASM32\INCLUDE\kernel32.inc
include \MASM32\INCLUDE\ntdll.inc

includelib \MASM32\LIB\kernel32.lib
includelib \MASM32\LIB\ntdll.lib

.data
IsDebugged			dd 			0
szHello				db 			'Hola mundo',0
exhandler 			dd 			0

.code 

start:

;=============================================
;		kernel32!IsDebuggerPresent 
;	técnica sencilla, es un método que mira 
;	el offset 2 en el PEB (esto se puede hacer a mano)
;=============================================

call IsDebuggerPresent
test eax,eax
jnz @DebuggerDetected


;=============================================
;		PEB!IsDebugged
;	Técnica como la anterior, pero esta vez
;	miramos el PEB nosotros a mano
;=============================================

mov eax,fs:[030h]
mov ebx,byte[eax+2]
test ebx,ebx
jnz @DebuggerDetected


;=============================================
;		PEB!NtGlobalFlags
;	Offset 0x68 dentro del PEB este valor 
;	estos flags valdrán 0x70 si están en
;	un debugger
;=============================================

mov ebx,[eax+68h]
and ebx,070h
test ebx,ebx
jnz @DebuggerDetected



;=============================================
;		Heap flags
;	Los flags del heap no se crean igual
;	cuando el proceso está debuggeado, por tanto
;	miraremos eso 
;=============================================

mov ebx,[eax+18h] ; process heap
mov ebx,[ebx+10h] ; heap flags
test ebx,ebx
jne @DebuggerDetected


;=============================================
;		Windows Vista anti-debug
;	Checkea valores en el main thread TEB, en el offset 0xBFC
;	el cual si se está debugeando contiene un puntero a un string 
;	UNICODE referenciando una dll del sistema.
;	Si el proceso no está debugeandose el puntero se establece a NULL
;=============================================

call GetVersion
cmp al,6
jne @NotVista
push offset _seh
push dword fs:[0]
mov fs:[0],esp
mov ebx,fs:[18h] ; teb 
add ebx, 0BFCh 
mov ecx,[ebx] ; puntero al string unicode
test ecx,ecx ; (ntdll.dll,gdi32.dll)
jz @DebuggerNotFound
sub ecx,ebx ; el unicode string sigue el puntero
sub ecx,4   
jne @DebuggerNotFound
jmp @DebuggerDetected


@DebuggerNotFound:
@NotVista:
;=============================================
;		NtQueryInformationProcess
;	Esto se trata de un wrapper de ZwQueryInformationProcess
;	cuando se le llama con ProcessInformationClass puesto a 7 (OricessDebugPort)
;	establece ProcessInformation a -1
;	Es muy potente como antidebugging y no hay manera
;	fácil de evitarlo.
;	Otra solución es usar un driver de sistema que hooke
;	la llamada ZwNtQueryInformationProcess
;=============================================
push 0
push 4
push offset IsDebugged
push 7 ; ProcessDebugPort
push -1
call NtQueryInformationProcess
test eax, eax
jne @ExitError

cmp IsDebugged,0
jnz @DebuggerDetected


;=============================================
;		kernel32!CheckRemoteDebuggerPresent
;	Api que toma dos parámetros: un handle a proceso y un puntero 
;	a un DWORD. Si fue bien, el DWORD valdrá 1 si el proceso
;	está siendo debuggeado
;=============================================
push offset IsDebugged
push -1
call CheckRemoteDebuggerPresent
test eax,eax
jnz @DebuggerDetected


;=============================================
;		UnhandledExceptionFilter
;	Provocamos una excepción que hará que el programa
;	si está siendo debuggeado, termine
;=============================================

push @not_debugged
call SetUnhandledExceptionFilter
xor eax,eax
mov eax, dword [eax] ; forzamos NULL Pointer exception
; el programa aquí terminaría si estuviera siendo debuggeado

@not_debugged:
	; procesamos la excepción y continuamos
	mov esp, dword ptr[esp+8] ; recuperamos la pila
    mov fs:[0],esp ; metemos en fs[0] el puntero del handler del sistema

;=============================================
;		NtSetInformationThread
;	wrapper de ZwSetInformationThread cuando se le llama 
;	ThreadInformationClass se establece a 0x11 (ThreadHideFromDebugger)
;	Si se está en un debugger el hilo se desacopla
;=============================================
push 0
push 0
push 11h ; ThreadHideFromDebugger
push -2
call NtSetInformationThread
; el thread se desacoplaría si estuviera siendo debuggeado

;=============================================
;		kernel32!CloseHandle y NtClose
;	Usando ZwClose es posible detectar un debugger 
;	ya que si se realiza esta llamada con un handle inválido
;	generará STATUS_INVALID_HANDLE (0xC0000008)
;=============================================
push offset @not_debugged2
push dword fs:[0]
mov fs:[0],esp
push 1234h ; un handle inválido
call CloseHandle
; si caemos aquí, el proceso está siendo debuggeado
jmp @DebuggerDetected


@not_debugged2:


;=============================================
;		kernel32!OutputDebugStringA
;	técnica muy inteligente, llamando a este método
;	con un ascii correcto, la llamada nos devolverá
;	un puntero a ese string, eso significa que está 
;	siendo debuggeado
;=============================================
xor eax,eax
push offset szHello
call OutputDebugStringA
cmp eax,1
jne @DebuggerDetected


;=============================================
; 		CTRL-C
;	Hay que levantar una excepción EXCEPTION_CTL_C
;	el handler de señal sería llamado si el programa no es
;	debuggeado
;=============================================
push offset exhandler
push 1
call RtlAddVectoredExceptionHandler
push 1
push sighandler 
call SetConsoleCtrlHandler
push 0
push CTRL_C_EVENT
call GenerateConsoleCtrlEvent
push 10000
call Sleep 
push 0
call ExitProcess

exhandler:
;checkear si EXCEPTION_CTL_C, si así es,
;debugger detectado, debería salir
ret
sighandler:
;continuar


;=============================================
; 		Rogue INT3
;	técnica para engañar a debuggers básicos.
;	consiste en insertar un INT3 en medio de una 
;	secuencia válida en medio de una secuencia
;	válida de instrucciones. Cuando es ejecutado
;	si el programa no es debuggeado, el control
;	se pasará al handler de excepciones y la ejecución
;	continuará.
;	Como INT3 lo usan los debuggers para establecer 
;	breakpoints software, insertando uno, puede usarse
;	para engañar al debugger y hacerle creer es un breakpoint 
;	así el control no sería pasado al handler de excepción.
;=============================================
push offset @handler 
push dword fs:[0]
mov fs:[0],esp

db 0CCh
; si cae aquí es que está siendo debugueado
jmp @DebuggerDetected

@handler:
; continuamos la ejecución


;=============================================
;		"ICE" breakpoint
;	instrucción indocumentada de Intel, opcode 0xF1
;	usado para detectar programas de traceo.
; 	ejecutar esta instrucción generará una excepción
;	SINGLE_STEP. Si el programa ya está traceado
;	el debugger pensará es una excepción generada normal
; 	el handler asociado no será ejecutado, y la ejecución 
;	no continuará como se esperaba
;	Bypassear esto es fácil, una puede pasar la instrucción
;	en lugar de ir con F8. La excepción será generada, pero 
;	desde que el programa no es traceado, debugger debería
;	entender que tiene que pasar el control al handler 
;=============================================
push offset @handler2
push dword fs:[0]
mov  fs:[0],esp

db 0F1h
; si cae aquí es un debugger
jmp @DebuggerDetected

@handler2:
; seguimos ejecución


;=============================================
;		Interrupt 2Dh
;	Ejecutar esta instrucción si el programa no está 
;	debuggeandose levantará una excepción de breakpoint 
;	Si el programa está ejecutado, y la instrucción 
;	no es ejecutada con el flag trace, no se levantará
;	una excepción, y la ejecución continuará normal.
;	Si está debuggeandose y la instrucción traceada,
;	el siguiente byte será pasado y la ejecución continuará.
;=============================================

push offset @handler3
push dword fs:[0]
mov fs:[0],esp

db 02Dh
mov eax,1 ;anti-tracing
jmp @DebuggerDetected

@handler3:
; continua ejecución


;=============================================
;		Timestamp counters
;	Usando contadores de alta precisión, que guardan
;	el actual número de ciclos de CPU desde el arranque
;	puede ser preguntado con RDTSC. Técnicas clasicas
;	de antidebugging, consisten en medir tiempos delta
;	en puntos clave, y ver si ese delta es demasiado alto
;	en tal caso es que se está debuggeando 
;=============================================
push offset @handler4
push dword ptr fs:[0]
mov fs:[0],esp
rdtsc 
push eax 
xor eax,eax
div eax ; manda excepción 
rdtsc 
sub eax,[esp] ; obtén el delta
pop fs:[0]
add esp,4
cmp eax,10000h ; límite de tiempo máximo posible
ja @DebuggerDetected

@handler4:
mov ecx,[esp+0Ch]
add dword ptr[ecx+0B8h],2 ; saltate div 
xor eax,eax
ret

;=============================================
;		popf and the trap flag
;	el flag trap, en los registros de flag controla
;	el traceo del programa. Si este flag es establecido
;	ejecutando una instrucción también levantará una 
;	excepción de SINGLE_STEP. Este flag se puede modificar
;	del siguiente modo:
;=============================================
pushf
mov dword[esp],0100h
popf


;=============================================
;		Stack Segment register
;	Técnica muy original anti-traceo. Usado en un packer
;	conocido como MarCrypt. COnsiste en tracear sobre
;	esta secuencia de instrucciones
;=============================================
push ss 
pop ss ;al ejecutar esta instrucción, la siguiente se ejecutará sin parar en ella, parando directamente en el NOP
pushf
nop

; en el pacer se usa de la siguiente manera
push ss 
; junk
pop ss 
pushf	
; junk, popf se ejecutará de manera implicita
pop eax
and eax,0100h
or eax,eax
jnz @DebuggerDetected

;=============================================
;		Debug registers manipulation
;	Los registros de Debug (DR0 hasta DR7) son usados 
;	para establecer breakpoints de hardware
;	Una protección puede manipularlos para detectar 
;	qué hardware breakpoints han sido establecidos,
;	resetearlos o establecerlos a lugar particulares
;	usados para realizar código de checkeo.
;	Packers como tElock hacen uso de registros de debug para 
;	prevenir ingeniería inversa.
;	Desde el modo usuario, los registros de debug no pueden
;	ser establecidos usando 'mov drx,...' pero hay otras formas 
;	- Generando una excepción el contexto del hilo es modificado, y luego volver a la ejecución normal con nuevo contexto.
;	- Usando NtGetContextThread y NtSetContextThread (disponible en kernel32 con GetThreadContext y SetThreadContext).
;	Veremos la primera forma 
;=============================================
push offset @handler5
push dword ptr fs:[0]
mov fs:[0],esp
xor eax,eax 
div eax ;genera excepción
pop fs:[0]
add esp,4
; continúa ejecución
; ...
@handler5:
	mov ecx,[esp+0Ch] ;pasa div
	add dword ptr [ecx+0B8h],2 ;pasa div 
	mov dword ptr [ecx + 04h],0 ; limpia dr0
	mov dword ptr [ecx + 08h],0 ; limpia dr1
	mov dword ptr [ecx + 0Ch],0 ; limpia dr2
	mov dword ptr [ecx + 10h],0 ; limpia dr3
	mov dword ptr [ecx + 14h],0 ; limpia dr6
	mov dword ptr [ecx + 18h],0 ; limpia dr7
	xor eax,eax
	ret


@DebuggerDetected:
	
	ret

end start