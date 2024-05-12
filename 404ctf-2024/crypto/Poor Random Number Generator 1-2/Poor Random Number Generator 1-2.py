from pwn import *
from z3 import *
import os

from Crypto.Util.number import bytes_to_long, long_to_bytes

class Generator:
	def __init__(self):
		self.feed = [int.from_bytes(os.urandom(1)) for i in range(2000)]

	def get_next_byte(self):
		number = 0

		for i in range(len(self.feed)):
			if i%2==0:
				number += pow(self.feed[i],i,2**8) + self.feed[i]*i
				number = ~number
			else:
				number ^= self.feed[i]*i+i

		number %= 2**8
		self.feed = self.feed[1:]
		self.feed.append(number)
		return number

	def get_random_bytes(self,length):
		random = b''

		for i in range(length):
			random += long_to_bytes(self.get_next_byte())

		return random



flag_part = open('../flag.png.part', 'rb').read()
flag_enc = open('../flag.png.enc', 'rb').read()

keytream = xor(flag_part, flag_enc)[:len(flag_part)]
keytream = [bytes_to_long(bytes([x])) for x in keytream]

g = Generator()
g.feed = keytream[1:2001]
g.get_random_bytes(len(keytream)-2001)

missing = len(flag_enc) - len(flag_part)
keytream += g.get_random_bytes(missing)

flag = xor(keytream, flag_enc)
open('flag.png', 'wb').write(flag)

# 404CTF{5294dbe4adf1fd96b34635abc07c6a5dba3be8bf}