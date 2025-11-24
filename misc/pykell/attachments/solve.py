from pwn import *

context.log_level = 'ERROR'
with open("./solve_extreme_s.pyk", "r") as f:
    solve = f.read()

pi = "π".encode()

r = remote(args.ADDR, args.PORT, ssl=args.SSL)

if args.TOKEN:
    r.sendlineafter(b"token:", args.TOKEN.encode())

lines = solve.splitlines()
for line in lines[:-1]:
    r.sendlineafter(pi + b" ", line.encode())
r.sendlineafter(b"1", b"FLAG")
flag = r.recvuntil(b"}").decode()
print(flag)
