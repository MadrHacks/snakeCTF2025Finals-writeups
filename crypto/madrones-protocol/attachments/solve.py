#!/usr/bin/env python3
from scapy.all import rdpcap
from hashlib import sha3_224
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f'{len(a) = }\n{len(b) = }'
    return bytes([x ^ y for x, y in zip(a, b)])


def decrypt_pkt(idx: int, key: bytes) -> bytes:
    global packets
    target_pkt = packets[idx]["UDP"].load[21:]
    iv, ct = target_pkt[:16], target_pkt[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16)


packets = rdpcap(f"challenge.pcap")
uav_port, gs_port = packets[0]["UDP"].sport, packets[0]["UDP"].dport
uav_1_packets = packets.filter(lambda p: (p.sport == uav_port and p.dport == gs_port)
                                         or (p.sport == gs_port and p.dport == uav_port))

# Focus on the auth packets of the first uav
auth_messages = []
for pkt in uav_1_packets[:4]:
    auth_messages.append(pkt["UDP"].load)

# The first message has the structure 0x01 || tuid || n_a || h(psk||tuid||n_a)
# and we need to extract the nonce n_a from it
n_a = auth_messages[0][21:41]

# The second message has the structure
# 0x02 || q || hash
# where q = n_b xor n_a xor k1 || n_a xor k_1 xor k_2
q = auth_messages[1][1:41]
q_lhs, q_rhs = q[:20], q[20:]
shared_secret_first_half = xor(n_a, q_lhs)
k1_xor_k2 = xor(q_rhs, n_a)

# The third message has the structure
# 0x03 || tuid || M || N || hash
N = auth_messages[2][61:81]
shared_secret_second_half = xor(k1_xor_k2, N)
shared_secret = shared_secret_first_half + shared_secret_second_half
skey = sha3_224(shared_secret).digest()[:16]


# Now that we have the key, we can decrypt messsage 11(or 10) which contains
# the session key between the two UAVs
target_pkt = packets[10]["UDP"].load[1:] if packets[10]["UDP"].dport == uav_port else packets[9]["UDP"].load[1:]
iv, ct = target_pkt[:16], target_pkt[16:]
cipher = AES.new(skey, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)

# The key we are looking for is in the last 16 bytes
uav_session_key = pt[-16:]

# Now we just need to decrypt the last two packets of the capture
# to retrieve the flag
flag = b''
delim = b': '
pt = decrypt_pkt(11, uav_session_key)
idx = pt.index(delim)
flag += pt[idx + len(delim):]

pt = decrypt_pkt(12, uav_session_key)
idx = pt.index(delim)
flag += pt[idx + len(delim):]
print(flag.decode())
