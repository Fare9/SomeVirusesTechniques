.486
.model flat,stdcall
option casemap:none
assume fs:nothing

.data

dato db 'FindClose',0

.code

start:

	push offset dato
	call mystrlen
	push offset dato
	push eax
	call crc32Cipher
	ret
	
	crc32Cipher proc 
    ;===============================================================
    ;			Cifrado tipo CRC32 para los nombres 
    ;			de las funciones 
    ;===============================================================
    	push ebp
    	mov  ebp, esp
    	push ebx
		push ecx
		push edx
		push esi
		push edi
		mov esi, [ebp + 0Ch]
		mov ecx, [ebp + 08h]
		xor eax, eax
		cdq
		dec edx

		_punset_1:

			lodsb
			xor al, dl
			push ecx
			movzx ebx, al
			push 8
			pop ecx

		loc_401335:

			test bl, 1
			jz short loc_401344
			shr ebx, 1
			xor ebx, 0FEA36969h
			jmp short loc_401346

		loc_401344:
			shr ebx, 1

		loc_401346:

			loop loc_401335
			pop ecx
			shr edx, 8
			xor edx, ebx
			loop _punset_1
			xchg eax, edx
			not eax

			pop edi
			pop esi
			pop edx
			pop ecx
			pop ebx
    		leave
    		retn 8
    crc32Cipher endp

    mystrlen proc
    ;===============================================================
    ;			Función para contar caracteres
    ;===============================================================
    	push ebp
    	mov ebp,esp
    	push ecx
    	push esi

    	mov esi,[ebp + 08h]

    	_cuenta123:
    		lodsb
    		test al,al
    		jz _aLaVerga

    		inc ecx
    		jmp _cuenta123

    	_aLaVerga:
    		mov eax, ecx
    		pop esi 
    		pop ecx 
    		leave
    		retn 4
    mystrlen endp


end start
