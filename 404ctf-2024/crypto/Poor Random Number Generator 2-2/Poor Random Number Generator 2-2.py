from pwn import *
import os
import random as rd
from z3 import *

from Crypto.Util.number import bytes_to_long, long_to_bytes

flag_part = open('../flag.png.part', 'rb').read()
flag_enc = open('../flag.png.enc', 'rb').read()

keytream_bytes = xor(flag_part, flag_enc)[:len(flag_part)]
keytream = []
for K in keytream_bytes:
	keytream.extend([int(x) for x in list(format(K, '08b'))])


class LFSR:
	def __init__(self, key, taps):
		d = max(taps)
		assert len(key) == d, "Error: key of wrong size."
		self._s = key
		self._t = [d - t for t in taps]

	def _sum(self, L):
		s = 0
		for x in L:
			s = s ^ x
		return s

	def _clock(self):
		b = self._s[0]
		self._s = self._s[1:] + [self._sum(self._s[p] for p in self._t)]
		return b

	def bit(self):
		return self._clock()
	
class Jeff:
	def __init__(self, key):
		assert len(key) <= 19 + 19 + 19
		self.LFSR = [
			LFSR(key[00:19], [19,5,2,1]),
			LFSR(key[19:38], [19,6,2,1]),
			LFSR(key[38:57], [19,9,8,5]),
		]

	def bit(self):
		b = [lfsr.bit() for lfsr in self.LFSR]
		return (b[0] & b[1])^(b[0] & b[2])^(b[1] & b[2])

	def bytes(self):
		byte = 0
		for i in range(8):
			bit = self.bit()
			byte += int(bit)*2**(7-i)
		return byte.to_bytes(length = 1,byteorder='big')


s = Solver()
KEY = [BitVec(f"k_{i}", 1) for i in range(3*19)]
J = Jeff(KEY)

for b in keytream:
	s.add(J.bit() == b)

assert s.check() == sat

initial_state = ''.join([str(s.model()[k]) for k in KEY])

state1 = [int(x) for x in initial_state[00:19]][::-1]
state2 = [int(x) for x in initial_state[19:38]][::-1]
state3 = [int(x) for x in initial_state[38:57]][::-1]

print(state1)
print(state2)
print(state3)

KEY = [int(x) for x in initial_state]
J = Jeff(KEY)

keytream = b''
for _ in range(len(flag_enc)):
	keytream += J.bytes()

flag = xor(keytream, flag_enc)
open('flag.png', 'wb').write(flag)


# 404CTF{82f4b68aee8d377ada3ca5f7ff8933b6f18aca05}

# combine = lambda x1,x2,x3 : (x1 and x2)^(x1 and x3)^(x2 and x3)

# print(f'x1 | x2 | x3  -> combine(x1, x2, x3)')
# print()
# for x1 in (0, 1):
# 	for x2 in (0, 1):
# 		for x3 in (0, 1):
# 			r = combine(x1, x2, x3)
# 			print(f'{x1} | {x2} | {x3}  -> {r}')

"""
x1 | x2 | x3  -> combine(x1, x2, x3)

0 | 0 | 0  -> 0
0 | 0 | 1  -> 0
0 | 1 | 0  -> 0
0 | 1 | 1  -> 1
1 | 0 | 0  -> 0
1 | 0 | 1  -> 1
1 | 1 | 0  -> 1
1 | 1 | 1  -> 1
"""