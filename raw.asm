use64
; mov rax, 1
; push 0
; mov r8, rsp
; add dword [r8], 0x12345678
; sub dword [r8], 0x12345678
; add r8, 0x12345678

; mov rsp, rbp
; pop rbp
; push rbp
; mov rbp, rsp
; ; add to r8 and allocate stack to fit
; sub r8, 0x12345678
; start:
; cmp r8, rsp
; jnb stop
; push 0
; jmp start
; stop:

; mov rax, 1
; mov rdi, 1
; mov rsi, r8
; mov rdx, 1
; syscall

; cmp dword [r8], 0
; jne 0x12345678

; mov rax, 0xffffffffffffffff
; mov rax, 0xffffffff
; mov rax, 0x1122334455667788
; ret

; add byte [r8], 69
; sub byte [r8], 69
; add r8, 69
; sub r8, 69
; cmp byte [r8], 0
nop
