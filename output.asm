format ELF64 executable 3
segment readable executable
print:
    mov     r9, -3689348814741910323
    sub     rsp, 40
    mov     BYTE [rsp+31], 10
    lea     rcx, [rsp+30]
.L2:
    mov     rax, rdi
    lea     r8, [rsp+32]
    mul     r9
    mov     rax, rdi
    sub     r8, rcx
    shr     rdx, 3
    lea     rsi, [rdx+rdx*4]
    add     rsi, rsi
    sub     rax, rsi
    add     eax, 48
    mov     BYTE [rcx], al
    mov     rax, rdi
    mov     rdi, rdx
    mov     rdx, rcx
    sub     rcx, 1
    cmp     rax, 9
    ja      .L2
    lea     rax, [rsp+32]
    mov     edi, 1
    sub     rdx, rax
    xor     eax, eax
    lea     rsi, [rsp+32+rdx]
    mov     rdx, r8
    mov     rax, 1
    syscall
    add     rsp, 40
    ret

entry start
start:
    push rbp
    mov rbp, rsp
    sub rsp, 8
    mov rax, [rbp-0]
    mov rdi, rax
    call print
    mov rax, 69
    mov [rbp-0], rax
    mov rax, 0
    mov [rbp-1], rax
    mov rsp, rbp
    pop rbp
    mov rax, 60
    mov rdi, 0
    syscall
