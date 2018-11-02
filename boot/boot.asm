FALSE   EQU     0
TRUE    EQU     NOT FALSE

IBMVER  EQU     true 
IBM     EQU     IBMVER
MSVER   EQU     false   

HIGHMEM EQU     FALSE   
KANJI   EQU     false   
IBMJAPAN        EQU     FALSE

IFDEF   IBM
        INCLUDE IFEQU.ASM
ENDIF


SYM     EQU     ">"

LINPERPAG       EQU     23
NORMPERLIN      EQU     1
WIDEPERLIN      EQU     5
COMBUFLEN       EQU     128     

DRVCHAR         EQU     "i?"

FCB     EQU     5CH

VARSTRUC        STRUC
ISDIR   DB      ?
SIZ     DB      ?
TTAIL   DW      ?
INFO    DB      ?
BUF     DB      DIRSTRLEN + 20 DUP (?)
VARSTRUC        ENDS

WSWITCH EQU     1              
PSWITCH EQU     2               
ASWITCH EQU     4               
BSWITCH EQU     8               
VSWITCH EQU     10H             
GOTSWITCH EQU   8000H    
ASSUME  CS:TRANGROUP,DS:TRANGROUP,ES:TRANGROUP,SS:NOTHING


SEARCHNEXT:
        MOV     AH,DIR_SEARCH_NEXT
        TEST    [SRCINFO],2
        JNZ     SEARCH                  
        OR      AH,AH                   
        return
SEARCH:
        PUSH    AX
        MOV     AH,SET_DMA
        MOV     DX,OFFSET TRANGROUP:DIRBUF
        INT     int_command             
        POP     AX                      

        jmp     COPERR

COPYLP:
        mov     bx,[SRCHAND]
        mov     cx,[BYTCNT]
        mov     dx,[NXTADD]
        sub     cx,dx                   
        jnz     GOTROOM
        call    FLSHFIL
        CMP     [TERMREAD],0
        JNZ     end
        mov     cx
GOTROOM:
        push    ds
        mov     ds,[TPA]
ASSUME  DS:NOTHING
        mov     ah,READ
        INT     int_command
        pop     ds
ASSUME  DS:TRANGROUP
        jc      CLOSESRC                
        mov     cx,ax                   
        jcxz    CLOSESRC                
        cmp     [SRCISDEV],0
        jnz     NOTESTA                 
        cmp     [ASCII],0
        jz      BINREAD
NOTESTA:
        MOV     DX,CX
        MOV     DI,[NXTADD]
        MOV     AL,1AH
        PUSH    ES
        MOV     ES,[TPA]
        REPNE   SCASB                   
        POP     ES
        JNZ     USEALL
        INC     [RDEOF]
        INC     CX
USEALL:
        SUB     DX,CX
        MOV     CX,DX
BINREAD:
        ADD     CX,[NXTADD]
        MOV     [NXTADD],CX
        CMP     CX,[BYTCNT]           
        JB      TESTDEV                 
        CALL    FLSHFIL
        CMP     [TERMREAD],0
        JNZ     CLOSESRC                
        JMP     SHORT COPYLP

TESTDEV:
        cmp     [SRCISDEV],0
