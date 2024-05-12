from sage.all import *

from pwn import *
from base64 import b64decode
from zlib import decompress
from json import loads
from Crypto.Util.number import long_to_bytes



class client:
	def __init__(self, ip, port, debug=False) -> None:
		self.ip = ip
		self.port = port
		self.debug = debug
		if self.debug:
			self.io = process(['python3', 'challenge.py'])
		else:
			self.io = remote(self.ip, self.port)

	def shell(self):
		self.io.interactive()

	def read(self):
		self.io.recvuntil("mettre un peu d'ordre dans tout ça ?".encode())
		data = self.io.recvall().strip()
		data = b64decode(data)
		data = decompress(data)
		data = loads(data)
		return data['public_key'], data['encrypted']

def matrix_overview(BB):
    for i in range(BB.dimensions()[0]):
        a = '%03d '%i
        for j in range(BB.dimensions()[1]):
            if BB[i,j] == 0:
                a += ' '
            elif BB[i,j] == 1:
                a += '1'
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        a += '|'
        print(a)

def solver_knapsack(pub: list[int], s: int):
	# Calcul de N
	N = ceil(len(pub)**0.5 / 2) + 1
	print(f'N = {N}\n')
	# N = 2**256

	# Création de la matrice
	M = 2 * matrix.identity(len(pub))
	M = M.augment(2 * N * matrix(ZZ, pub).transpose())
	M = M.stack(-1 * matrix(ZZ,  [1 for _ in range(len(pub))] + [2 * N * s] ))

	print('Matrix: ')
	matrix_overview(M)

	# Réduction
	print('Running Reduction algo.')
	B = M.LLL()

	# Récupération des candidats potentiels.
	candidates = [Y for Y in B if abs(Y[-1]) == 0]
	print(f'Found {len(candidates)} candidate(s)')

	for C in candidates:
		for k in [-1,1]:
			# Récupération des m_i 
			C2 = [(-x+2)//2 for x in (k * vector(C))[:-1]]

			# Vérification de la solution trouvé.
			if all([x in [0, 1] for x in C2]):
				yield ''.join([str(int(x)) for x in C2])
				yield ''.join([str(int(x)) for x in C2[::-1]])

				# s1 = int(''.join([str(int(x)) for x in C2]), 2)
				# s2 = int(''.join([str(int(x)) for x in C2[::-1]]), 2)
				# yield s1
				# yield s2

	return False


c = client('challenges.404ctf.fr', 31777, debug=False)

pub, flag_enc = c.read()

for s in solver_knapsack(pub, flag_enc):
	s = int(s[:-2], 2) # jsp pourquoi 
	print(long_to_bytes(s))

'''

Running Reduction algo.
Found 234 candidate(s)
b'404CTF{uN_s4C_@_d0s_B13n_r4Ng3!}'
b'\x0b\xe8L\xceg"\xc4\xef\xa7l\xc8\xc4/\xac\xe0\xc2o\xa0/\xac"\xcc\xef\xa7*\xed\xe6"\xac"\xc0\xc2'
b'\x0b\xcf\xcb\xbc\xab\xb9\x84\x8a\xb1\xa0\x8c\xcb\xbc\xa0\xbf\xa0\x9b\xcf\x8c\xa0\xbd\xce\xcc\x91\xa0\x8d\xcb\xb1\x98\xcc\xde\x82'
b'4\x17\xb31\x98\xdd;\x10X\x937;\xd0S\x1f=\x90_\xd0S\xdd3\x10X\xd5\x12\x19\xddS\xdd?='
 sage  sage                                                                           

'''