;
;       Código para obtener la librería kernel32
;       Por medio del segmento FS, el cual apuntará
;       a NTDLL.dll, luego al propio módulo, y finalmente
;       a Kernel32.dll
;
;       @author: Fare9
;
;       Información sobre FS: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
;       Información sobre PEB: https://en.wikipedia.org/wiki/Process_Environment_Block, https://www.aldeid.com/wiki/PEB-Process-Environment-Block
;       Información sobre Ldr: https://www.aldeid.com/wiki/PEB_LDR_DATA
;       Información sobre InLoadOrderModuleList: https://www.aldeid.com/wiki/LDR_DATA_TABLE_ENTRY

.486
.model flat, stdcall
option casemap :none
.code ; posible añadir "code readable writable executable" para darle permisos de todo

start:

call delta

    delta:
        pop ebp
        sub ebp,delta ; Obtenemos en ebp el delta offset del programa

        jmp _init

ddKernel32Base          dd          0
ddGetProcAddress        dd          0
ddLoadLibrary           dd          0
frase                   db          'Ojete de vaca',0
user32Lib               db          'user32.dll',0
function                db          'MessageBoxA',0
         
        ; Comienzo real del codigo
        _init:
            assume fs: nothing
            mov edi, dword ptr fs:[030h] ; Pillamos el PEB del Win32_Thread_Information_Block
            mov edi, dword ptr [edi+0Ch] ; Del PEB pillamos la lista Ldr
            mov edi, dword ptr [edi+0Ch] ; De la lista Ldr pillamos InLoadOrderModuleList  (lista enlazada tipo LIST_ENTRY
            ; edi ya apunta a NTDLL, haremos que apunte al módulo y seguido a kernel32
            mov edi, dword ptr [edi] ; Apunta al módulo
            mov edi, dword ptr [edi] ; Apunta a Kernel32
            
            ; Muevo la base de kernel32 a una variable
            mov edx, dword ptr [edi+018h]
            cmp word ptr [edx], 'ZM' ; Comparo con MZ, si no es así, pues ACM1PT
            jnz ACM1PT
            mov [ebp+ddKernel32Base], edx

            
        ; Ahora obtenemos GetProcAddress
            call GiveMeGetProcAddress
            mov [ebp+ddGetProcAddress],eax

        ; Obtenemos LoadLibrary
            call GiveMeLoadLibrary
            mov [ebp+ddLoadLibrary],eax

            
            lea ebx,[ebp+user32Lib]
            
            mov eax,[ebp+ddLoadLibrary]
            push ebx
            call eax

            lea ebx,[ebp+function]
            push ebx
            push eax
            mov eax,[ebp+ddGetProcAddress]
            call eax

            xor ecx,ecx
            lea ebx,[ebp+frase]
            push ecx
            push ebx
            push ebx
            push ecx
            call eax
            
   ACM1PT:

        ret

   GiveMeGetProcAddress:
        mov edi, [ebp+ddKernel32Base]
        
        mov eax, dword ptr [edi+03ch]  ; Obtenemos RVA de cabecera PE
        add eax, edi ; direccion absoluta de cabecera PE

        mov esi, dword ptr [eax+078h] ; Obtenemos el RVA de la exportTable
        add esi, edi ; ExportTable direccion absoluta

        mov edx, dword ptr [esi+020h] ; AddressOfNames
        add edx,edi
        
        xor ecx, ecx
        bucle:
            mov eax, dword ptr [edx] ; Offset de un nombre
            add eax,edi ; obtenemos la dirección absoluta
            cmp dword ptr [eax],'PteG'
            jnz NoPs
            cmp dword ptr [eax+4h],'Acor'
            jnz NoPs
            cmp dword ptr [eax+8h],'erdd'
            jnz NoPs
            jmp DPM
       NoPs:
            add edx, 4h ; Apuntamos al siguiente método
            inc ecx
            jmp bucle
       DPM:
            ; Ahora en ECX tenemos el número de desplazamiento de GetProcAddress
            rol ecx, 1h
            mov edx, dword ptr [esi+24h] ; AddressOfNameOrdinals
            add edx, edi ; Obtenemos dirección absoluta de AddressOfNameOrdinals
            add edx, ecx
            movzx ecx, word ptr [edx] ; Offset de la direccion de la funcion
            
            mov edx, dword ptr [esi+01ch] ; RVA de AddressOfFunctions
            add edx, edi ; Direccion absoluta AddressOfFunctions
            rol ecx,2h ; Multiplicamos ecx por 4
            add edx, ecx ; Offset de la dirección
            mov eax, dword ptr [edx]
            add eax, edi ; Sumamos la base del kernel
            
            ret
            
  GiveMeLoadLibrary:
        mov edi, [ebp+ddKernel32Base]
        
        mov eax, dword ptr [edi+03ch]  ; Obtenemos RVA de cabecera PE
        add eax, edi ; direccion absoluta de cabecera PE

        mov esi, dword ptr [eax+078h] ; Obtenemos el RVA de la exportTable
        add esi, edi ; ExportTable direccion absoluta

        mov edx, dword ptr [esi+020h] ; AddressOfNames
        add edx,edi
        
        xor ecx, ecx
        bucle2:
            mov eax, dword ptr [edx] ; Offset de un nombre
            add eax,edi ; obtenemos la dirección absoluta
            cmp dword ptr [eax],'daoL'
            jnz NoPs2
            cmp dword ptr [eax+4h],'rbiL'
            jnz NoPs2
            jmp DPM2
       NoPs2:
            add edx, 4h ; Apuntamos al siguiente método
            inc ecx
            jmp bucle2
       DPM2:
            ; Ahora en ECX tenemos el número de desplazamiento de GetProcAddress
            rol ecx, 1h
            mov edx, dword ptr [esi+24h] ; AddressOfNameOrdinals
            add edx, edi ; Obtenemos dirección absoluta de AddressOfNameOrdinals
            add edx, ecx
            movzx ecx, word ptr [edx] ; Offset de la direccion de la funcion
            
            mov edx, dword ptr [esi+01ch] ; RVA de AddressOfFunctions
            add edx, edi ; Direccion absoluta AddressOfFunctions
            rol ecx,2h ; Multiplicamos ecx por 4
            add edx, ecx ; Offset de la dirección
            mov eax, dword ptr [edx]
            add eax, edi ; Sumamos la base del kernel
            
            ret

end start