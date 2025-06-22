format ELF64 executable 3

segment readable executable

SYS_WRITE = 1
STDOUT = 1

entry start
start:
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [msg]
    mov rdx, len
    syscall

    mov rax, 60
    mov rdi, 0
    syscall

segment readable writable

msg db "Hello, World!", 10
len db $-msg
