;-----------------------------------------------
;----------- DEFINICION ESTRUCTURA -------------
;-----------------------------------------------

PROCESSENTRY32  STRUCT

    dwSize              dd      ?
    cntUsage            dd      ?
    th32ProcessID       dd      ?
    th32DefaultHeapID   dd      ?
    th32ModuleID        dd      ?
    cntThreads          dd      ?
    th32ParentProcessID dd      ?
    pcPriClassBase      dd      ?
    dwFlags             dd      ?
    szExeFile           db      260 DUP (?)

PROCESSENTRY32  ENDS