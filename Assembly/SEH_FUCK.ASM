;
;	Programa para ver como modificar el handler
;	de error SEH de windows
;

.486
.model flat, stdcall
.stack 100h
option casemap :none

.code

start:

	xor edi,edi
	push dword ptr fs:[edi] ; meto en la pila el manejador de excepción normal
	mov fs:[edi],offset SEH_Handler  ; meto un nuevo manejador
	mov eax, dword ptr ds:[esp+8] ; valor de la dirección de retorno del primer CreateProcess (dentro de Kernel32.dll)
	and eax, 0FFFF0000h ; establezco a 0 los dos primeros bytes
	Bucle:
		sub eax,10000h ; voy restando 1 a ver si llego a la cabecera Kernel32
		cmp word ptr[eax],'ZM' ; miro a ver si es la cabecera 
		jnz Bucle
	SEH_Handler:
		; para cuidar si accedo a una página de memoria sin permisos de lectura
		mov esp, dword ptr ds:[esp+8] ;restauro la pila, por si peta el programa
		jmp Bucle 

end start