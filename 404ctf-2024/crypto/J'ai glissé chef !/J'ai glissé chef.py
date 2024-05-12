from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from random import randint
from tqdm import tqdm
from itertools import product

from challenge import Feistel, Sbox

context.log_level = 'critical'

class client:
    def __init__(self, ip, port, debug) -> None:
        self.ip = ip
        self.port = port
        self.debug = debug

        if self.debug:
            self.io = process(['python3', "challenge.py"])
        else:
            self.io = remote(ip, port) 
        self.io.recvuntil(b'<key2>')
        self.io.recvline()
        self.io.recvline()

    def shell(self) -> None:
        self.io.interactive()

    def check(self, K0: int, K1: int) -> bytes:
        K0 = hex(K0)
        K1 = hex(K1)
        self.io.sendline(f'check {K0} {K1}'.encode())
        res = self.io.recvline().strip().decode()
        print(res)
        return res
    
    def encrypt_stuff(self, data: list[int]) -> int:
        plain = '\nencrypt '.join([long_to_bytes(x).hex() for x in data])
        self.io.sendline(f'encrypt {plain}'.encode())
        res = [int(self.io.recvline().strip().decode(), 16) for _ in range(64)]
        return res    
        
    def decrypt_stuff(self, data: list[int]) -> int:
        plain = '\ndecrypt '.join([long_to_bytes(x).hex() for x in data])
        self.io.sendline(f'decrypt {plain}'.encode())
        res = [int(self.io.recvline().strip().decode(), 16) for _ in range(64)]
        return res     
  
    def encrypt(self, data: int) -> int:
        plain = long_to_bytes(data).hex()
        self.io.sendline(f'encrypt {plain}'.encode())
        res = self.io.recvline().strip().decode()
        return int(res, 16)
    
    def decrypt(self, data: int) -> int:
        plain = long_to_bytes(data).hex()
        self.io.sendline(f'decrypt {plain}'.encode())
        res = self.io.recvline().strip().decode()
        return int(res, 16)


class Pair:
    def __init__(self, x, y) -> None:
        self.x = x
        self.y = y
        self.split()

    def split(self):
        self.x_l = self.x >> 32
        self.x_r = self.x & 0xFFFFFFFF

        self.y_l = self.y >> 32
        self.y_r = self.y & 0xFFFFFFFF

    def __repr__(self) -> str:
        return f'Pair({self.x}, {self.y})'

def f_inv(block):
    Sbox_inv = [Sbox.index(x) for x in range(len(Sbox))]
    b4 = (block>>24) & 0xff
    b3 = (block>>16) & 0xff
    b2 = (block>>8) & 0xff
    b1 = block & 0xff
    b4 ^= b3
    b4 = Sbox_inv[b4]
    b3 = Sbox_inv[b3]
    b3 ^= b1
    b1 ^= b2
    b2 = Sbox_inv[b2]
    b2 ^= b1
    b1 = Sbox_inv[b1]
    return (b1<<24)+(b2<<16)+(b3<<8)+b4

def get_pairs(save: bool = False):
    enc_k0, dec_k0 = [], []
    enc_k1, dec_k1 = [], []

    base_right = randint(2**31, 2**32-1)

    ask_enc = []
    ask_dec = []
    for _ in tqdm(range(2**16)):
        x1 = randint(2**31, 2**32-1) << 32 | base_right & 0xFFFFFFFF
        x2 = randint(2**31, 2**32-1) << 32 | base_right & 0xFFFFFFFF
        ask_enc.append(x1)
        ask_dec.append(x2)

    ciphered = [c.encrypt_stuff(ask_enc[i:i+64]) for i in range(0, len(ask_enc), 64)]
    deciphered = [c.decrypt_stuff(ask_dec[i:i+64]) for i in range(0, len(ask_dec), 64)]

    for i, res_part in enumerate(ciphered):
        for k in range(len(res_part)):
            enc_k0.append(Pair(x=ask_enc[k+64*i],y=res_part[k]))

    for i, res_part in enumerate(deciphered):
        for k in range(len(res_part)):
            dec_k0.append(Pair(x=ask_dec[k+64*i],y=res_part[k]))



    base_left = randint(2**31, 2**32-1) << 32
    ask_enc = []
    ask_dec = []
    for _ in tqdm(range(2**16)):
        x1 = base_left | randint(2**31, 2**32-1) & 0xFFFFFFFF
        x2 = base_left | randint(2**31, 2**32-1) & 0xFFFFFFFF
        ask_enc.append(x1)
        ask_dec.append(x2)
    
    ciphered = [c.encrypt_stuff(ask_enc[i:i+64]) for i in range(0, len(ask_enc), 64)]
    deciphered = [c.decrypt_stuff(ask_dec[i:i+64]) for i in range(0, len(ask_dec), 64)]

    for i, res_part in enumerate(ciphered):
        for k in range(len(res_part)):
            enc_k1.append(Pair(x=ask_enc[k+64*i],y=res_part[k]))

    for i, res_part in enumerate(deciphered):
        for k in range(len(res_part)):
            dec_k1.append(Pair(x=ask_dec[k+64*i],y=res_part[k]))

    if save:
        open('./save/enc_k0.txt', 'w').write(str(enc_k0))
        open('./save/dec_k0.txt', 'w').write(str(dec_k0))
        open('./save/enc_k1.txt', 'w').write(str(enc_k1))
        open('./save/dec_k1.txt', 'w').write(str(dec_k1))

    return enc_k0, dec_k0, enc_k1, dec_k1

def load_pairs():
    enc_k0 = eval(open("./save/enc_k0.txt", "r").read())
    dec_k0 = eval(open("./save/dec_k0.txt", "r").read())
    enc_k1 = eval(open("./save/enc_k1.txt", "r").read())
    dec_k1 = eval(open("./save/dec_k1.txt", "r").read())
    return enc_k0, dec_k0, enc_k1, dec_k1 


def find_K0(enc, dec):
    found = []
    down_right = [from_down.y_r for from_down in dec]
    dr_set = set(down_right)
    for from_up in tqdm(enc):                                # On cherche un N == R'       
        if from_up.y_r in dr_set:                            # Si N dans les R'       
            from_down = dec[down_right.index(from_up.y_r)]   # Je récup la bonne paires avec le bon R'
            if from_up.y_r != from_down.y_r:                 # Si N == R'
                continue
            K0 = f_inv(from_up.y_l ^ from_down.y_l) ^ from_down.y_r
            found.append(K0)
    return found

def find_K1(enc, dec):
    found = []
    down_left = [from_down.y_l for from_down in dec]
    dl_set = set(down_left)
    for from_up in tqdm(enc):
        if from_up.y_l in dl_set:
            from_down = dec[down_left.index(from_up.y_l)]
            if from_up.y_l != from_down.y_l:
                continue
            K1 = f_inv(from_up.y_r ^ from_down.y_r) ^ from_up.y_l
            found.append(K1)
    return found

c = client('challenges.404ctf.fr', 31953, debug=False)

enc_k0, dec_k0, enc_k1, dec_k1 = get_pairs(save=True)
# enc_k0, dec_k0, enc_k1, dec_k1 = load_pairs()

all_k0 = find_K0(enc_k0, dec_k0)
all_k1 = find_K1(enc_k1, dec_k1)

print("K0 candidates: ", [hex(K0) for K0 in all_k0])
print("K1 candidates: ", [hex(K1) for K1 in all_k1])

y_ref = long_to_bytes(c.encrypt(bytes_to_long(b'VERIF123')))

for K0, K1 in product(list(set(all_k0)), list(set(all_k1))):
    key = long_to_bytes(K0) + long_to_bytes(K1)
    cipher = Feistel(Sbox,key)
    if cipher.encrypt(b'VERIF123') == y_ref:
        print('Key found: ', K0, K1)
        c.check(K0, K1)

"""
# A lancer pleins de fois

$ python3 solve.py
100%|█████████████████████████████████████████████████████████| 65536/65536 [00:00<00:00, 858255.90it/s]
100%|█████████████████████████████████████████████████████████| 65536/65536 [00:00<00:00, 938130.64it/s]
100%|████████████████████████████████████████████████████████| 65536/65536 [00:00<00:00, 4715695.78it/s]
100%|████████████████████████████████████████████████████████| 65536/65536 [00:00<00:00, 4297250.21it/s]
K0 candidates:  ['0x67218ac5', '0x67218ac5', '0x67218ac5']
K1 candidates:  ['0x380b46d', '0x380b46d', '0x380b46d', '0xb496ad3a', '0x6ff0fb65']
Key found:  1730251461 58766445
Congratulations ! 404CTF{m0R3_ROuNd5_d0es_NoT_me4n_MoR3_53cURiTy}
"""