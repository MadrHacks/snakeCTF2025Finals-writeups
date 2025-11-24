import base64

from pwn import *

HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
SSL = args.SSL
r = remote(HOST, PORT, ssl=SSL)

if args.TEAM_TOKEN:
    r.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())

with open("solve", "rb") as f:
    data = f.read()

data = base64.b64encode(data)

r.sendlineafter(">", data)

r.interactive()
