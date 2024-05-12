import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *
from z3 import *

from Crypto.Util.number import long_to_bytes,bytes_to_long

context.log_level = 'critical'

class client:
	def __init__(self, ip: str, port: int, local: bool=False) -> None:
		if local:
			self.io = process(['python3', 'challenge.py'])
		else:
			self.io = remote(ip, port)
		
	def shell(self) -> None:
		self.io.interactive()

	def close(self) -> None:
		self.io.close()

	def get_info(self) -> list[bytes, bytes]:
		self.io.recvuntil(b'hash :')
		plain = bytes.fromhex(self.io.recvline().strip().decode())
		self.io.recvuntil(b'Hash :')
		hashed = bytes.fromhex(self.io.recvline().strip().decode())
		return plain, hashed

	def submit(self, pre_image: bytes) -> str:
		self.io.recvuntil(b'> ')
		self.io.sendline(pre_image.hex().encode())
		result = self.io.recvline().strip()
		print(result.decode())


class Bob_sym:
	def __init__(self, data):
		self.R_size = 32
		self.C_size = 96
		self.OUT_size = 512

		K = [int(x) for x in format((len(data)//8)%256, '08b')]
		data = K + data + K
		data += [0 for _ in range(self.R_size - len(data)%self.R_size)]

		self.data = data
		self.state = [
			[0 for _ in range(self.R_size)],
			[0 for _ in range(self.C_size)]
		]

	def xor(self,a,b):
		return [(i+j) for i,j in zip(a,b)]

	def _f(self):
		perm = [65, 107, 53, 90, 67, 35, 17, 100, 37, 103, 41, 92, 23, 120, 70, 11, 34, 73, 16, 29, 7, 91, 127, 69, 81, 26, 0, 98, 71, 51, 9, 112, 64, 121, 101, 47, 114, 30, 104, 113, 3, 27, 6, 32, 42, 93, 48, 21, 118, 99, 89, 84, 36, 110, 25, 102, 61, 39, 86, 50, 14, 10, 56, 28, 38, 62, 22, 46, 66, 19, 108, 18, 13, 125, 49, 2, 74, 95, 8, 122, 58, 5, 75, 97, 15, 63, 117, 123, 96, 24, 94, 43, 4, 33, 115, 45, 76, 80, 126, 109, 52, 12, 79, 72, 54, 77, 31, 57, 1, 87, 88, 60, 20, 55, 40, 111, 116, 44, 82, 85, 68, 105, 106, 83, 78, 124, 59, 119]
		input_perm = self.state[0].copy() + self.state[1].copy()

		output_perm = [input_perm[i] for i in perm]
		self.state = [
			output_perm[:self.R_size],
			output_perm[self.R_size:]
		]

	def _absorb(self):
		while len(self.data) != 0:
			input_data = self.data[:self.R_size]
			self.state[0] = self.xor(self.state[0],input_data)
			self.data = self.data[self.R_size:]
			self._f()

	def _squeeze(self):
		output = []
		while len(output) != self.OUT_size:
			output += self.state[0].copy()
			self._f()

		return output

	def digest(self):
		self._absorb()
		hash_out = self._squeeze()
		return hash_out

	def hexdigest(self):
		return self.digest().hex()

def matrix_overview(BB):
	for i in range(BB.dimensions()[0]):
		a = '%02d '%(i+1)
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

def poly2vect(poly):
	try:
		C = [int(str(x[1])[2:]) for x in list(poly) if 'k' in str(x[1])]
		C = [1 if x in C else 0 for x in range(8*chars)]
		T = 1 if (1, 1) in list(poly) else 0	
		return C, T
	except:
		nul = [0 for x in range(8*chars)]
		return [nul, GF(2)(poly)]



# Connection
c = client('challenges.404ctf.fr', 31952, local=False)

# Get target as bytes
plain, hashed = c.get_info()
print(f'Target bytes: {hashed.hex()}\n')

# Get target as binary
hashed_bin = []
for b in hashed:
	hashed_bin.extend([int(x) for x in format(b, '08b')])
print(f'Target bin  : {hashed_bin}\n')


# Verify that "plain" is a solution:
solution_bin = []
for b in plain:
	solution_bin.extend([int(x) for x in format(b, '08b')])
print(f'Solution bin  : {solution_bin}\n')

chars = 32

letter = ','.join([f'k_{j}' for j in range(8*chars)])
R = PolynomialRing(GF(2), letter)

key_bits = list(R.gens())

digest_sim = Bob_sym(key_bits).digest()


target = vector([GF(2)(x) for x in hashed_bin])

M = []
T = []

for k in range(len(digest_sim)):
	C, bit = poly2vect(digest_sim[k])
	M.append(C)
	T.append(target[k] + bit)


M = Matrix(GF(2), M).T
T = Matrix(GF(2), T)


try:
	S = M.solve_left(T).row(0)
except:
	print('No solution found !')
	exit()

result = Bob_sym(list(S)).digest()
assert hashed_bin == result

assert sum(Matrix(S * M) - T) == 0


S = ''.join([str(x) for x in S])
pre_image = bytes([int(S[i:i+8],2) for i in range(0, len(S), 8)])


c.submit(
	pre_image = pre_image
)
c.close()

# 404CTF{p4dD1nG_1s_A_tRIckY_0p3r@TiOn_bUt_g0od_cHeckS_aR3_aN_H4rd3r_0n3}