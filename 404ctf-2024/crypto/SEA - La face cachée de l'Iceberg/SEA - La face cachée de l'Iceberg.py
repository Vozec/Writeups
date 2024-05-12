
import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from random import randint
from tqdm import tqdm
import itertools
import concurrent.futures


from sea import SEA, SBOX_1, SBOX_2


context.log_level = 'critical'

ascii_fbox = '''
   .... X1 ....|.... X2 ....|.... X3 ....|.... X4 ....|.... X5 ....|.... X6 ....|.... X7 ....|.... X8 ....|
        |            |            |            |            |            |            |            |
     00000001     00000002     00000003     00000004     00000005     00000006     00000007     00000008
        |            |            |            |            |            |            |            |
        |            X -----------|            X -----------|            |------------X            |
        |            |            |            |            |            |            |            |
        |         00000009        |         00000017        |            |         00000021        |
        |            |            |            |            |            |            |            |
        X -----------|            |            |            |            |            |            |
        |            |            |            |            |            |            |            |
     00000010        |            |            |            |            |            |            |
        |            |            |            |            |            |            |            |
        S1           |            |            S2           |            S1           |            |
        |            |            |            |            |            |            |            |
     00000011        |            |         00000018        |         00000022        |            |
        |            |            |            |            |            |            |            |
        |------------X            |            |------------X            |------------X            |
        |            |            |            |            |            |            |            |
        |         00000012        |            |         00000019        |         00000023        |
        |            |            |            |            |            |            |            |
        |            S2           |            |            S1           |            S2           |
        |            |            |            |            |            |            |            |
        |         00000013        |            |         00000020        |         00000024        |
        |            |            |            |            |            |            |            |
        |            |------------X            |            |            X------------|------------X
        |            |            |            |            |            |            |            |
        |            |         00000014        |            |         00000026        |         00000025
        |            |            |            |            |            |            |            |
        |            |            S2           |            |            |            |            S1
        |            |            |            |            |            |            |            |
        |            |         00000015        |            |            |            |         00000027
        |            |            |            |            |            |            |            |
        |          ---            |            |            |            |            |            |
        |----------|--------------X            |            |            |            |            |
        |          ---            |            |            |            |            |            |
        |            |         00000016        |            |            |            |            |
        |            |            |            |            |            |            |            |
        |            |            |            |            |            |            |            |
        |            |            |            |            |------------|---------   |            |
        |            |            |            |                         |        |   |            |
        |            |            |            |------------|            |      --|---|------------|
        |            |            |                         |            |      | |   |            
        -------------------------------------->|            |            |      | |   |------------|
                     |            |            |            |      ------|      | |                |
        |<------------            |            |            |      |            | |---             |
        |                         |            |            |      |            |    |             |
        |            <-------------            |            |      |            |    |             |
        |            |                         |            |      |            |    |             |
        |            |            |<-----------|--------------------     |-------    |             |
        |            |            |            |            |            |           |             |
        |            |            |            |            |            |           |             |
        v            v            v            v            v            v           v             v
     00000028     00000029     00000030     00000031     00000032     00000033     00000034      00000035
'''

class client:
	def __init__(self, ip: str, port: int, local: bool=True) -> None:
		self.local = local
		self.ip = ip
		self.port = port
		self.ENCRYPTION_NUMBER = 64
		if local:
			self.io = process(['python3', 'sea.py'])
		else:
			self.io = remote(ip, port)

	def shell(self):
		self.io.shell()

	def get_flag_enc(self):
		self.io.recvuntil(b'secret :')
		flag_enc = self.io.recvline().strip().decode()
		self.flag_enc = bytes.fromhex(flag_enc)
		return self.flag_enc

	def encrypt(self, plain):
		self.io.recvuntil(b'please) > ')
		self.io.sendline(long_to_bytes(plain).hex().encode())
		r = self.io.recvline().strip()
		if b'Too' in r:
			print(f'Error: "{r.decode()}"')
			return 0
		c = bytes_to_long(bytes.fromhex(r.decode()))

		print(f'[DEBUG] N°{self.ENCRYPTION_NUMBER:02} | FEAL({plain}) = {c}')
		self.ENCRYPTION_NUMBER -= 1
		return c

def colorize(text):
	text = text.replace('0', 'ZERO')
	text = text.replace('1', 'UN')
	text = text.replace('ZERO', '\033[91m0\033[0m')
	text = text.replace('UN', '\033[92m1\033[0m')
	return text



def f_diff(block1, block2, print_ascii:bool=False,debug=False):
	fbox = ascii_fbox

	b1_1 = (block1>>56)		
	b1_2 = (block2>>56)
	fbox = fbox.replace('00000001', format(b1_1^b1_2,'08b'));
	
	b2_1 = (block1>>48) & 0xff 
	b2_2 = (block2>>48) & 0xff 
	fbox = fbox.replace('00000002', format(b2_1^b2_2,'08b'));
	
	b3_1 = (block1>>40) & 0xff 
	b3_2 = (block2>>40) & 0xff 
	fbox = fbox.replace('00000003', format(b3_1^b3_2,'08b'));
	
	b4_1 = (block1>>32) & 0xff 
	b4_2 = (block2>>32) & 0xff 
	fbox = fbox.replace('00000004', format(b4_1^b4_2,'08b'));
	
	b5_1 = (block1>>24) & 0xff 
	b5_2 = (block2>>24) & 0xff 
	fbox = fbox.replace('00000005', format(b5_1^b5_2,'08b'));
	
	b6_1 = (block1>>16) & 0xff 
	b6_2 = (block2>>16) & 0xff 
	fbox = fbox.replace('00000006', format(b6_1^b6_2,'08b'));
	
	b7_1 = (block1>>8) & 0xff  
	b7_2 = (block2>>8) & 0xff  
	fbox = fbox.replace('00000007', format(b7_1^b7_2,'08b'));
	
	b8_1 = block1 & 0xff       
	b8_2 = block2 & 0xff       
	fbox = fbox.replace('00000008', format(b8_1^b8_2,'08b'));


	b2_1 ^= b3_1  
	b2_2 ^= b3_2
	fbox = fbox.replace('00000009', format(b2_1^b2_2,'08b'));
	
	b1_1 ^= b2_1  
	b1_2 ^= b2_2
	fbox = fbox.replace('00000010', format(b1_1^b1_2,'08b'));
	
	b1_1 = SBOX_1[b1_1]         
	b1_2 = SBOX_1[b1_2]         
	fbox = fbox.replace('00000011', format(b1_1^b1_2,'08b'));
	
	b2_1 ^= b1_1
	b2_2 ^= b1_2  
	fbox = fbox.replace('00000012', format(b2_1^b2_2,'08b'));
	
	b2_1 = SBOX_2[b2_1]         
	b2_2 = SBOX_2[b2_2]         
	fbox = fbox.replace('00000013', format(b2_1^b2_2,'08b'));
	
	b3_1 ^= b2_1  
	b3_2 ^= b2_2  
	fbox = fbox.replace('00000014', format(b3_1^b3_2,'08b'));
	
	b3_1 = SBOX_2[b3_1]         
	b3_2 = SBOX_2[b3_2]         
	fbox = fbox.replace('00000015', format(b3_1^b3_2,'08b'));
	
	b3_1 ^= b1_1  
	b3_2 ^= b1_2  
	fbox = fbox.replace('00000016', format(b3_1^b3_2,'08b'));
	
	b4_1 ^= b5_1  
	b4_2 ^= b5_2  
	fbox = fbox.replace('00000017', format(b4_1^b4_2,'08b'));
	
	b4_1 = SBOX_2[b4_1]         
	b4_2 = SBOX_2[b4_2]         
	fbox = fbox.replace('00000018', format(b4_1^b4_2,'08b'));
	
	b5_1 ^= b4_1  
	b5_2 ^= b4_2  
	fbox = fbox.replace('00000019', format(b5_1^b5_2,'08b'));
	
	b5_1 = SBOX_1[b5_1]         
	b5_2 = SBOX_1[b5_2]         
	fbox = fbox.replace('00000020', format(b5_1^b5_2,'08b'));

	b7_1 ^= b6_1  
	b7_2 ^= b6_2  
	fbox = fbox.replace('00000021', format(b7_1^b7_2,'08b'));
	
	b6_1 = SBOX_1[b6_1]         
	b6_2 = SBOX_1[b6_2]         
	fbox = fbox.replace('00000022', format(b6_1^b6_2,'08b'));
	
	b7_1 ^= b6_1  
	b7_2 ^= b6_2  
	fbox = fbox.replace('00000023', format(b7_1^b7_2,'08b'));
	
	b7_1 = SBOX_2[b7_1]         
	b7_2 = SBOX_2[b7_2]         
	fbox = fbox.replace('00000024', format(b7_1^b7_2,'08b'));
	
	b8_1 ^= b7_1  
	b8_2 ^= b7_2  
	fbox = fbox.replace('00000025', format(b8_1^b8_2,'08b'));
	
	b6_1 ^= b7_1  
	b6_2 ^= b7_2  
	fbox = fbox.replace('00000026', format(b6_1^b6_2,'08b'));
	
	b8_1 = SBOX_1[b8_1]         
	b8_2 = SBOX_1[b8_2]         
	fbox = fbox.replace('00000027', format(b8_1^b8_2,'08b'));

	fbox = fbox.replace('00000028', format(b2_1^b2_2,'08b'));
	fbox = fbox.replace('00000029', format(b3_1^b3_2,'08b'));
	fbox = fbox.replace('00000030', format(b6_1^b6_2,'08b'));
	fbox = fbox.replace('00000031', format(b1_1^b1_2,'08b'));
	fbox = fbox.replace('00000032', format(b4_1^b4_2,'08b'));
	fbox = fbox.replace('00000033', format(b8_1^b8_2,'08b'));
	fbox = fbox.replace('00000034', format(b5_1^b5_2,'08b'));
	fbox = fbox.replace('00000035', format(b7_1^b7_2,'08b'));

	if print_ascii:
		fbox = colorize(fbox)
		print(fbox)

	return ((b2_1^b2_2)<<56)+((b3_1^b3_2)<<48)+((b6_1^b6_2)<<40)+((b1_1^b1_2)<<32)+((b4_1^b4_2)<<24)+((b8_1^b8_2)<<16)+((b5_1^b5_2)<<8)+(b7_1^b7_2)

def f(block, print_ascii:bool=False,debug=False):
		fbox = ascii_fbox

		b1 = (block>>56)        ;fbox = fbox.replace('00000001', format(b1,'08b'));
		b2 = (block>>48) & 0xff ;fbox = fbox.replace('00000002', format(b2,'08b'));
		b3 = (block>>40) & 0xff ;fbox = fbox.replace('00000003', format(b3,'08b'));
		b4 = (block>>32) & 0xff ;fbox = fbox.replace('00000004', format(b4,'08b'));
		b5 = (block>>24) & 0xff ;fbox = fbox.replace('00000005', format(b5,'08b'));
		b6 = (block>>16) & 0xff ;fbox = fbox.replace('00000006', format(b6,'08b'));
		b7 = (block>>8) & 0xff  ;fbox = fbox.replace('00000007', format(b7,'08b'));
		b8 = block & 0xff       ;fbox = fbox.replace('00000008', format(b8,'08b'));

		b2 ^= b3               ;fbox = fbox.replace('00000009', format(b2,'08b'));
		b1 ^= b2               ;fbox = fbox.replace('00000010', format(b1,'08b'));
		b1 = SBOX_1[b1]         ;fbox = fbox.replace('00000011', format(b1,'08b'));
		b2 ^= b1               ;fbox = fbox.replace('00000012', format(b2,'08b'));
		b2 = SBOX_2[b2]         ;fbox = fbox.replace('00000013', format(b2,'08b'));
		b3 ^= b2               ;fbox = fbox.replace('00000014', format(b3,'08b'));
		b3 = SBOX_2[b3]         ;fbox = fbox.replace('00000015', format(b3,'08b'));
		b3 ^= b1               ;fbox = fbox.replace('00000016', format(b3,'08b'));
		b4 ^= b5               ;fbox = fbox.replace('00000017', format(b4,'08b'));
		b4 = SBOX_2[b4]         ;fbox = fbox.replace('00000018', format(b4,'08b'));
		b5 ^= b4               ;fbox = fbox.replace('00000019', format(b5,'08b'));
		b5 = SBOX_1[b5]         ;fbox = fbox.replace('00000020', format(b5,'08b'));
		b7 ^= b6               ;fbox = fbox.replace('00000021', format(b7,'08b'));
		b6 = SBOX_1[b6]         ;fbox = fbox.replace('00000022', format(b6,'08b'));
		b7 ^= b6               ;fbox = fbox.replace('00000023', format(b7,'08b'));
		b7 = SBOX_2[b7]         ;fbox = fbox.replace('00000024', format(b7,'08b'));
		b8 ^= b7               ;fbox = fbox.replace('00000025', format(b8,'08b'));
		b6 ^= b7               ;fbox = fbox.replace('00000026', format(b6,'08b'));
		b8 = SBOX_1[b8]         ;fbox = fbox.replace('00000027', format(b8,'08b'));

		fbox = fbox.replace('00000028', format(b2,'08b'));
		fbox = fbox.replace('00000029', format(b3,'08b'));
		fbox = fbox.replace('00000030', format(b6,'08b'));
		fbox = fbox.replace('00000031', format(b1,'08b'));
		fbox = fbox.replace('00000032', format(b4,'08b'));
		fbox = fbox.replace('00000033', format(b8,'08b'));
		fbox = fbox.replace('00000034', format(b5,'08b'));
		fbox = fbox.replace('00000035', format(b7,'08b'));

		if print_ascii:
			fbox = colorize(fbox)
			print(fbox)

		return (b2<<56)+(b3<<48)+(b6<<40)+(b1<<32)+(b4<<24)+(b8<<16)+(b5<<8)+b7

def splt(m: int) -> list[int]:
	return [
		(m>>56),(m>>48) & 0xff,
		(m>>40) & 0xff,(m>>32) & 0xff,
		(m>>24) & 0xff,(m>>16) & 0xff,
		(m>>8) & 0xff,m & 0xff,
	]

def fbox_splitter_in(y: int, pad: bool=False) -> list[int]:
	b1 = (y >> 56);
	b2 = (y >> 48) & 0xff;
	b3 = (y >> 40) & 0xff;
	b4 = (y >> 32) & 0xff;
	b5 = (y >> 24) & 0xff;
	b6 = (y >> 16) & 0xff;
	b7 = (y >> 8) & 0xff;
	b8 = y & 0xff;

	if pad:
		return [
			(b1<<56)+(b2<<48)+(b3<<40)+(0<<32)+(0<<24)+(0<<16)+(0<<8)+0,
			(0<<56)+(0<<48)+(0<<40)+(b4<<32)+(b5<<24)+(0<<16)+(0<<8)+0,
			(0<<56)+(0<<48)+(0<<40)+(0<<32)+(0<<24)+(b6<<16)+(b7<<8)+b8
		]

	return [
		(b1 << 16) | (b2 << 8) | (b3 << 0),
		(b4 << 8)  | (b5 << 0),
		(b6 << 16) | (b7 << 8) | (b8 << 0)
	]

def join(m: list[int]) -> int:
	return (m[0]<<56)+(m[1]<<48)+(m[2]<<40)+(m[3]<<32)+(m[4]<<24)+(m[5]<<16)+(m[6]<<8)+m[7]

def repr(m: list[str]) -> int:
	return join([int(x,2) for x in m])

def split(state):
	return left(state), right(state)

def left(state):
	return state>>(16*4)

def right(state):
	return state & 0xffffffffffffffff

def b64(state):
	return format(state, '064b')

def bx(state, x):
	return format(state, '0%sb'%str(x))

def f_mid(y):
	b4 = (y >> 32) & 0xff;
	b5 = (y >> 24) & 0xff;
	
	b4 ^= b5
	b4 = SBOX_2[b4]
	b5 ^= b4
	b5 = SBOX_1[b5]

	#return (0<<56)+(0<<48)+(0<<40)+(0<<32)+(b4<<24)+(0<<16)+(b5<<8)+0
	return (b4<<24)+(0<<16)+(b5<<8)

def f_left(y):
	b1 = (y>>56);
	b2 = (y>>48) & 0xff;
	b3 = (y>>40) & 0xff;

	b2 ^= b3
	b1 ^= b2
	b1 = SBOX_1[b1]
	b2 ^= b1
	b2 = SBOX_2[b2]
	b3 ^= b2
	b3 = SBOX_2[b3]
	b3 ^= b1

	# return (b2<<56)+(b3<<48)+(0<<40)+(b1<<32)+(0<<24)+(0<<16)+(0<<8)+0
	return (b2<<56)+(b3<<48)+(b1<<32)+(0<<24)

def f_right(y):
	b6 = (y >> 16) & 0xff;
	b7 = (y >> 8) & 0xff;
	b8 = y & 0xff;

	b7 ^= b6
	b6 = SBOX_1[b6]
	b7 ^= b6
	b7 = SBOX_2[b7]
	b8 ^= b7
	b6 ^= b7
	b8 = SBOX_1[b8]
	
	#return (0<<56)+(0<<48)+(b6<<40)+(0<<32)+(0<<24)+(b8<<16)+(0<<8)+b7
	return (b6<<40)+(b8<<16)+b7


def brute_round(paires, target):
	left_prob, mid_prob, right_prob = {}, {}, {}

	# Découpage des bloc en 3 parties => pour pas bf 2**64 mais 2**24 + 2**16 + 2**24
	masks = [0xFFFF00FF00000000, 0x00000000FF00FF00, 0x0000FF0000FF00FF]
	target_1, target_2, target_3 = [target & m for m in masks]

	for x1, x2, y1, y2 in paires:
		l1, r1 = split(y1)
		l2, r2 = split(y2)

		l1, r1 = r1, l1
		l2, r2 = r2,  l2

		l1_1, l1_2, l1_3 = [l1 & m for m in masks]
		l2_1, l2_2, l2_3 = [l2 & m for m in masks]

		r1_1, r1_2, r1_3 = fbox_splitter_in(r1, pad=True)
		r2_1, r2_2, r2_3 = fbox_splitter_in(r2, pad=True)

		delta_ref_1 = l1_1 ^ l2_1
		delta_ref_2 = l1_2 ^ l2_2
		delta_ref_3 = l1_3 ^ l2_3

		target_1_opti = target_1 ^ delta_ref_1
		target_2_opti = target_2 ^ delta_ref_2
		target_3_opti = target_3 ^ delta_ref_3

		# Bruteforce de la partie de gauche
		# Bf entier sur le premier et recheck des solutions sur les suivants
		possible = tqdm(range(0, 256**3)) if left_prob == {} else list(left_prob.keys())
		for candidate in possible:
			partial_1 = candidate << 40

			r1_left_out = f_left(r1_1 ^ partial_1)
			r2_left_out = f_left(r2_1 ^ partial_1)

			if (r1_left_out^r2_left_out) == target_1_opti:
				if candidate in left_prob:
					left_prob[candidate] += 1
				else:
					left_prob[candidate] = 1

		# Bruteforce de la partie du milieu
		# Bf entier sur le premier et recheck des solutions sur les suivants
		possible = range(0, 256**2) if mid_prob == {} else list(mid_prob.keys())
		for candidate in possible:
			partial_2 = candidate << 24

			r1_mid_out = f_mid(r1_2 ^ partial_2)
			r2_mid_out = f_mid(r2_2 ^ partial_2)
			
			if (r1_mid_out^r2_mid_out) == target_2_opti:
				if candidate in mid_prob:
					mid_prob[candidate] += 1
				else:
					mid_prob[candidate] = 1
					

		# Bruteforce de la partie de droite
		# Bf entier sur le premier et recheck des solutions sur les suivants
		possible = tqdm(range(0, 256**3)) if right_prob == {} else list(right_prob.keys())
		for partial_3 in possible:
			r1_right_out = f_right(r1_3 ^ partial_3)
			r2_right_out = f_right(r2_3 ^ partial_3)
			if (r1_right_out^r2_right_out) == target_3_opti:
				if partial_3 in right_prob:
					right_prob[partial_3] += 1
				else:
					right_prob[partial_3] = 1
					
	left_prob  = sorted(left_prob.items(), key=lambda x:x[1])
	mid_prob   = sorted(mid_prob.items(), key=lambda x:x[1])
	right_prob = sorted(right_prob.items(), key=lambda x:x[1])

	if sum([len(left_prob), len(mid_prob), len(right_prob)]) < 3:
		return []

	left_max  = max([x[1] for x in left_prob]) 
	mid_max   = max([x[1] for x in mid_prob]) 
	right_max = max([x[1] for x in right_prob]) 

	left_candidate  = [x[0] for x in left_prob  if x[1] == left_max]
	mid_candidate   = [x[0] for x in mid_prob   if x[1] == mid_max]
	right_candidate = [x[0] for x in right_prob if x[1] == right_max]

	combinaisons = list(itertools.product(left_candidate, mid_candidate, right_candidate))

	subkeys = [
		(left << 40) + (mid << 24) + (right)
		for left, mid, right in combinaisons
	]

	return subkeys

def brute_last_round(paires):
	def rebuild_subkeys(left_prob, mid_prob, right_prob):
		subkeysK0, subkeysK1 = [], []
		combinaisons = itertools.product(left_prob.items(), mid_prob.items(), right_prob.items())
		for combi in list(combinaisons):
			subkey1 = (combi[0][0] << 40) + (combi[1][0] << 24) + (combi[2][0])
			subkey0 = combi[0][1] | combi[1][1] | combi[2][1]
			subkeysK1.append(subkey1)
			subkeysK0.append(subkey0)
		return subkeysK0, subkeysK1

	left_prob, mid_prob, right_prob = {}, {}, {}
		
	masks_left  = [0xFFFF00FF00000000, 0x00000000FF00FF00, 0x0000FF0000FF00FF]
	masks_right = [0xFFFFFF0000000000, 0x000000FFFF000000, 0x0000000000FFFFFF]

	x1, y1 = paires[0]
	x2, y2 = paires[1]

	l1, r1 = split(y1)
	l2, r2 = split(y2)

	l1, r1 = r1, l1
	l2, r2 = r2, l2

	l1_1, l2_1, l3_1 = [l1 & m for m in masks_left]
	l1_2, l2_2, l3_2 = [l2 & m for m in masks_left]

	r1_1, r2_1, r3_1 = fbox_splitter_in(r1, pad=True)
	r1_2, r2_2, r3_2 = fbox_splitter_in(r2, pad=True)

	for candidate in range(0, 256**2):
		partial_1 = candidate << 40
		partial_2 = candidate << 24
		partial_3 = candidate

		left_found_1  = (l1_1 ^ f_left(r1_1 ^ partial_1)) & masks_left[0]
		left_found_2  = (l1_2 ^ f_left(r1_2 ^ partial_1)) & masks_left[0]

		mid_found_1   = (l2_1 ^ f_mid(r2_1 ^ partial_2)) & masks_left[1]
		mid_found_2   = (l2_2 ^ f_mid(r2_2 ^ partial_2)) & masks_left[1]

		right_found_1 = (l3_1 ^ f_right(r3_1 ^ partial_3)) & masks_left[2]
		right_found_2 = (l3_2 ^ f_right(r3_2 ^ partial_3)) & masks_left[2]


		round0_out_left_1  = ((left_found_1 << 64)  + (r1_1 & masks_right[0]))
		round0_out_left_2  = ((left_found_2 << 64)  + (r1_2 & masks_right[0]))

		round0_out_mid_1   = ((mid_found_1 << 64)   + (r2_1 & masks_right[1]))
		round0_out_mid_2   = ((mid_found_2 << 64)   + (r2_2 & masks_right[1]))

		round0_out_right_1 = ((right_found_1 << 64) + (r3_1 & masks_right[2]))
		round0_out_right_2 = ((right_found_2 << 64) + (r3_2 & masks_right[2]))
		

		subkey_0_guess_left_1  = (x1 ^ round0_out_left_1 ) & ((masks_left[0] << 64) + masks_right[0])
		subkey_0_guess_left_2  = (x2 ^ round0_out_left_2 ) & ((masks_left[0] << 64) + masks_right[0])

		subkey_0_guess_mid_1   = (x1 ^ round0_out_mid_1  ) & ((masks_left[1] << 64) + masks_right[1])
		subkey_0_guess_mid_2   = (x2 ^ round0_out_mid_2  ) & ((masks_left[1] << 64) + masks_right[1])

		subkey_0_guess_right_1 = (x1 ^ round0_out_right_1) & ((masks_left[2] << 64) + masks_right[2])
		subkey_0_guess_right_2 = (x2 ^ round0_out_right_2) & ((masks_left[2] << 64) + masks_right[2])

		if subkey_0_guess_left_1 == subkey_0_guess_left_2:
			left_prob[candidate]  = subkey_0_guess_left_1
		
		if subkey_0_guess_mid_1 == subkey_0_guess_mid_2:
			mid_prob[candidate]   = subkey_0_guess_mid_1
		
		if subkey_0_guess_right_1 == subkey_0_guess_right_2:
			right_prob[candidate] = subkey_0_guess_right_1
	
	if mid_prob == {}:
		return [], []

	for candidate in tqdm(range(256**2, 256**3)):
		partial_1 = candidate << 40
		partial_3 = candidate

		left_found_1  = (l1_1 ^ f_left(r1_1 ^ partial_1)) & masks_left[0]
		left_found_2  = (l1_2 ^ f_left(r1_2 ^ partial_1)) & masks_left[0]

		right_found_1 = (l3_1 ^ f_right(r3_1 ^ partial_3)) & masks_left[2]
		right_found_2 = (l3_2 ^ f_right(r3_2 ^ partial_3)) & masks_left[2]


		round0_out_left_1  = ((left_found_1 << 64)  + (r1_1 & masks_right[0]))
		round0_out_left_2  = ((left_found_2 << 64)  + (r1_2 & masks_right[0]))

		round0_out_right_1 = ((right_found_1 << 64) + (r3_1 & masks_right[2]))
		round0_out_right_2 = ((right_found_2 << 64) + (r3_2 & masks_right[2]))
		

		subkey_0_guess_left_1  = (x1 ^ round0_out_left_1 ) & ((masks_left[0] << 64) + masks_right[0])
		subkey_0_guess_left_2  = (x2 ^ round0_out_left_2 ) & ((masks_left[0] << 64) + masks_right[0])

		subkey_0_guess_right_1 = (x1 ^ round0_out_right_1) & ((masks_left[2] << 64) + masks_right[2])
		subkey_0_guess_right_2 = (x2 ^ round0_out_right_2) & ((masks_left[2] << 64) + masks_right[2])

		if subkey_0_guess_left_1 == subkey_0_guess_left_2:
			left_prob[candidate]  = subkey_0_guess_left_1
				
		if subkey_0_guess_right_1 == subkey_0_guess_right_2:
			right_prob[candidate] = subkey_0_guess_right_1
		

	for x, y in paires[2:]:
		new_left_prob, new_mid_prob, new_right_prob = {}, {}, {}

		l, r = split(y)
		l, r = r, l
		l1, l2, l3 = [l & m for m in masks_left]
		r1, r2, r3 = fbox_splitter_in(r, pad=True)

		for candidate in left_prob:
			partial_1 = candidate << 40
			left_found  = (l1 ^ f_left(r1 ^ partial_1))  & masks_left[0]
			round0_out_left  = ((left_found << 64)  + (r1 & masks_right[0]))
			subkey_0_guess_left  = (x ^ round0_out_left ) & ((masks_left[0] << 64) + masks_right[0])
			if left_prob[candidate] == subkey_0_guess_left:
				new_left_prob[candidate] = subkey_0_guess_left

		for candidate in mid_prob:
			partial_2 = candidate << 24
			mid_found   = (l2 ^ f_mid(r2 ^ partial_2))   & masks_left[1]
			round0_out_mid   = ((mid_found << 64)   + (r2 & masks_right[1]))
			subkey_0_guess_mid   = (x ^ round0_out_mid  ) & ((masks_left[1] << 64) + masks_right[1])
			if mid_prob[candidate] == subkey_0_guess_mid:
				new_mid_prob[candidate] = subkey_0_guess_mid

		for candidate in right_prob:
			partial_3 = candidate
			right_found = (l3 ^ f_right(r3 ^ partial_3)) & masks_left[2]
			round0_out_right = ((right_found << 64) + (r3 & masks_right[2]))			
			subkey_0_guess_right = (x ^ round0_out_right) & ((masks_left[2] << 64) + masks_right[2])
			if right_prob[candidate] == subkey_0_guess_right:
				new_right_prob[candidate] = subkey_0_guess_right
			
		left_prob = new_left_prob
		mid_prob = new_mid_prob
		right_prob = new_right_prob

	return rebuild_subkeys(left_prob, mid_prob, right_prob)


def brute_round_multithread(paires, targets:list, subkeysthread_count=16):
	with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(targets), thread_count)) as executor:
		futures = []
		for target in targets:
			thread = executor.submit(brute_round, paires, target)
			futures.append(thread)
		results = [future.result() for future in concurrent.futures.as_completed(futures)]
	return results


def undo_round(paires, subkey):
	new_pairs = []
	for x, y in paires:
		l, r = split(y)
		l, r = r, l
		l ^= f(r ^ subkey)
		new_pairs.append((x, (l<< 64) + r))
	return new_pairs

def undo_round_paires(paires, subkey):
	new_pairs = []
	for x1, x2, y1, y2 in paires:
		l1, r1 = split(y1)
		l2, r2 = split(y2)

		l1, r1 = r1, l1
		l2, r2 = r2, l2

		l1 ^= f(r1^subkey)
		l2 ^= f(r2^subkey)

		new_pairs.append((x1, x2, (l1<< 64) + r1, (l2<< 64) + r2))
	return new_pairs

def get_single(count=32):
	paires = []
	for i in range(count):
		x = randint(2**127, 2**128-1)
		y = c.encrypt(x)
		paires.append((x, y))
	return paires

def get_paires(differential, count=32):
	paires = []
	for i in range(count):
		x1 = randint(2**127, 2**128-1)
		x2 = x1 ^ differential
		paires.append([x1, x2, c.encrypt(x1), c.encrypt(x2)])
	return paires

def decrypt_flag(flag_enc, subkeys):
	def decrypt_bloc(bloc, subkeys):
		bloc_enc = [0, bloc]
		for subkey in subkeys[:-1]:
			bloc_enc = undo_round([bloc_enc], subkey)[0]
		return bloc_enc[1] ^ subkeys[-1]
	
	blocs = [bytes_to_long(flag_enc[i:i+16]) for i in range(0, len(flag_enc), 16)]
	dec = []
	for bloc in blocs:
		dec_bloc = decrypt_bloc(bloc, subkeys)
		dec.append(long_to_bytes(dec_bloc))
	return b''.join(dec)


# S1(x)⊕3 = S1(x⊕233)
# f(x)^f(x^16862322434457070313) = 847736350114560

c = client('challenges.404ctf.fr', 31951, local=False)
c.get_flag_enc()

threads_max = 100
target = repr(['00000000','00000011','00000011','00000011','00000000','00000011','00000011','00000000'])

""" 
paires_round4 = get_paires(
	differential = repr(['11101010','00000011','00000000','11101001','11101001','11101001','11101010','11101001']) << 64,
	count = 5 	
)
open('./save/paires_round4.txt', 'w').write(str(paires_round4))

paires_round3 = get_paires(
	differential = (0 << 64) + repr(['11101010','00000011','00000000','11101001','11101001','11101001','11101010','11101001']),
	count = 5
)
open('./save/paires_round3.txt', 'w').write(str(paires_round3))


paires_round2 = get_paires(
	differential = (0 << 64) + repr(['00000000','00000011','00000011','00000011','00000000','00000011','00000011','00000000']),
	count = 5
)
open('./save/paires_round2.txt', 'w').write(str(paires_round2))


paires_round1 = get_single(count=5)
open('./save/paires_round1.txt', 'w').write(str(paires_round1))


open('./save/save_flag.txt', 'wb').write(c.flag_enc)

print('Bruteforcing round 4')
round_4_subkeys = brute_round(paires_round4, target)
open('./save/save_round_4_subkeys.txt', 'w').write(str(round_4_subkeys))

print('Bruteforcing round 3')
round_3_subkeys = []
with concurrent.futures.ThreadPoolExecutor(max_workers=threads_max) as executor:
	futures = []
	for subkeys_4 in round_4_subkeys:
		paires_tmp = undo_round_paires(paires_round3, subkey=subkeys_4)
		thread = executor.submit(brute_round, paires_tmp, target)
		futures.append((
			[subkeys_4],
			thread
		))
	for path, result in futures:
		round_3_subkeys.append([path,result.result()])
open('./save/save_round_3_subkeys.txt', 'w').write(str(round_3_subkeys))



print('Bruteforcing round 2')
round_2_subkeys = []
with concurrent.futures.ThreadPoolExecutor(max_workers=threads_max) as executor:
	futures = []
	for guess in round_3_subkeys:
		path = guess[0]
		for subkeys_3 in guess[1]:
			subkeys_4 = path[0]
			paires_tmp = undo_round_paires(paires_round2, subkey=subkeys_4)
			paires_tmp = undo_round_paires(paires_tmp, subkey=subkeys_3)
			thread = executor.submit(brute_round, paires_tmp, target)
			futures.append((
				[subkeys_4, subkeys_3],
				thread
			))
	for path, result in futures:
		round_2_subkeys.append([path,result.result()])
open('./save/save_round_2_subkeys.txt', 'w').write(str(round_2_subkeys))
 """

c.flag_enc = open('./save/save_flag.txt', 'rb').read()
paires_round1 = eval(open('./save/paires_round1.txt', 'r').read())
round_2_subkeys = eval(open('./save/save_round_2_subkeys.txt', 'r').read())

print('Bruteforcing rounds 1 and 0')
round_1and0_subkeys = []
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
	futures = []
	for guess in round_2_subkeys:
		path = guess[0]
		for subkeys_2 in guess[1]:
			subkeys_4 = path[0]
			subkeys_3 = path[1]

			paires_tmp = undo_round(paires_round1, subkey=subkeys_4)
			paires_tmp = undo_round(paires_tmp, subkey=subkeys_3)
			paires_tmp = undo_round(paires_tmp, subkey=subkeys_2)
			thread = executor.submit(brute_last_round, paires_tmp)
			futures.append([
				[subkeys_4, subkeys_3, subkeys_2],
				thread
			])

	for path, result in futures:
		res = result.result()
		round_1and0_subkeys.append([path,res])
		
		round_1_subkeys = res[1]
		round_0_subkeys = res[0]
		for round_1_subkey, round_0_subkey in zip(round_1_subkeys, round_0_subkeys):
			subkeys = [path[0],	path[1], path[2], round_1_subkey, round_0_subkey]
			flag_dec = decrypt_flag(c.flag_enc, subkeys)
			print(flag_dec)

# 404CTF{C_3st_l_3nTr41neMent_qu1_P3rmEt_dE_Fa1re_lA_d1fF3RenC3_!}


open('./save/save_round_1&0_subkeys.txt', 'w').write(str(round_1and0_subkeys))


print('Deciphering all combinations')
path = round_1and0_subkeys[0][0]
round_1_subkeys = round_1and0_subkeys[0][1][1]
round_0_subkeys = round_1and0_subkeys[0][1][0]
for round_1_subkey, round_0_subkey in zip(round_1_subkeys, round_0_subkeys):
	subkeys = [path[0],	path[1], path[2], round_1_subkey, round_0_subkey]
	flag_dec = decrypt_flag(c.flag_enc, subkeys)
	if b'404CTF{' in flag_dec:
		print(flag_dec, subkeys)


exit()



#round_4_subkey = brute_round_multithread(paires_round4, [target])
# round_4_subkey = 129694652312198018

# paires_round3 = undo_round_paires(paires_round3, subkey=round_4_subkey)
# #round_3_subkey = brute_round_multithread(paires_round3, [target])
# round_3_subkey = 3491816373951539543

# paires_round2 = undo_round_paires(paires_round2, subkey=round_4_subkey)
# paires_round2 = undo_round_paires(paires_round2, subkey=round_3_subkey)
# #round_2_subkey = brute_round_multithread(paires_round2, [target])
# round_2_subkey = 10480488181677746188


# paires_round1 = undo_round(paires_round1, subkey=round_4_subkey)
# paires_round1 = undo_round(paires_round1, subkey=round_3_subkey)
# paires_round1 = undo_round(paires_round1, subkey=round_2_subkey)

# round_0_subkeys, round_1_subkeys = brute_last_round(paires_round1)

# for round_1_subkey, round_0_subkey in zip(round_1_subkeys, round_0_subkeys):
# 	flag_dec = decrypt_flag(c.flag_enc, [
# 		round_4_subkey,
# 		round_3_subkey,
# 		round_2_subkey,
# 		round_1_subkey,
# 		round_0_subkey
# 	])
# 	if b'404CTF{' in flag_dec:
# 		print(flag_dec)


'''
0x 0000000000000000000000e9e9000000|   00000000000000000000000000000000
In:00000000000000000000000000000000 -> 00000000000000000000000000000000|Round1 
In:0000000000000000000000e9e9000000 -> 00000000000000000000000000000300|Round2
In:00000000000000000000000000000300 -> 00000000000000000000XX0000YY00XX|Round3
In:00000000000
'''


'''
S1(x)⊕3 = S1(x⊕233)
=> 
- f(x^0xe9e9000000)^f(x) == 0x300
- f(x^0x0)^f(x) == 0x0


```python
x1 = randint(2**63, 2**64-1)
x2 = x1 ^ repr([
	'00000000','00000000','00000000',
	'11101001','11101001',
	'00000000','00000000','00000000'
])

y1 = f(x1, print_ascii=True)
y2 = f(x2, print_ascii=True)

print('Y1: ', colorize('     '.join([format(x, '08b') for x in splt(y1)])))
print('Y2: ', colorize('     '.join([format(x, '08b') for x in splt(y2)])))
print()
print(' Δ: ', colorize('     '.join([format(x, '08b') for x in splt(y1 ^ y2)])))
exit()
```

'''

'''
https://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/sbox.html#sage.crypto.sbox.SBox.linear_structures
https://github.com/PoustouFlan/SUnbox/tree/main

[main][/mnt/c/Users/vozec/Desktop/SUnbox]$ python3 main.py -in examples/sbox1 -auto
examples/sbox1

Automatic analysis.
SBox is not linear.
However, these equations hold with probability 67.19%:
y7 ⊕ y4 ⊕ y1 ⊕ y0 = x6 ⊕ x0
y6 ⊕ y2 = x6 ⊕ x2 ⊕ x1 ⊕ x0 ⊕ 1
y7 ⊕ y6 ⊕ y5 ⊕ y4 ⊕ y3 = x7 ⊕ x1 ⊕ x0
y7 ⊕ y6 ⊕ y2 ⊕ y1 ⊕ y0 = x7 ⊕ x3 ⊕ x1 ⊕ 1
y4 ⊕ y3 = x7 ⊕ x6 ⊕ x4 ⊕ x3 ⊕ x2 ⊕ x0 ⊕ 1
where y = S(x).

SBox is differential! For all x,
  S(x)⊕3 = S(x⊕233)

[main][/mnt/c/Users/vozec/Desktop/SUnbox]$ python3 main.py -in examples/sbox2 -auto
examples/sbox2

Automatic analysis.
SBox is not linear.
However, these equations hold with probability 62.5%:
	y1 ⊕ y0 = x1 ⊕ x0
	y7 ⊕ y5 = x3 ⊕ x1
	y6 ⊕ y5 ⊕ y4 ⊕ y3 ⊕ y1 ⊕ y0 = x5 ⊕ x3 ⊕ x2 ⊕ x1 ⊕ 1
	y5 ⊕ y3 ⊕ y2 ⊕ y1 = x6 ⊕ x5 ⊕ x4 ⊕ x3 ⊕ x1 ⊕ x0 ⊕ 1
	y3 ⊕ y1 = x7 ⊕ x5
where y = S(x).

+

```python
from sage.crypto.sbox import SBox 
from sage.crypto.sbox import feistel_construction

s1 = SBox(SBOX_1)
s2 = SBox(SBOX_2)

S = feistel_construction(s1, s2)
print(S.linear_structures())

for x in range(256):
	assert SBOX_1[x] == SBOX_1[x^233]^3
```
'''

'''


# Recherche de différentiel: 
for a in tqdm(range(256)):
	break
	for b in range(256):
		for c in range(256):
			x1 = randint(2**63, 2**64-1)
			x2 = randint(2**63, 2**64-1)
			x3 = randint(2**63, 2**64-1)
			diff = repr([
				b8(a),b8(b),b8(c),
				'11101001','11101001',
				'11101001','11101010','11101001'		
			])

			r1 = f_left(x1)^f_left(x1^diff)
			r2 = f_left(x2)^f_left(x2^diff)

			# r1 = f_diff(x1, x1^diff, print_ascii=False)
			# r2 = f_diff(x2, x2^diff, print_ascii=False)
			
			mask = 0xFFFF00FF00000000


			if (r1 & mask) == (r2 & mask):
				# r3 = f_diff(x3, x3^diff, print_ascii=False)
				r3 = f_left(x3)^f_left(x3^diff)
				if (r3 & mask) == (r1 & mask):
					print( b8(a), b8(b), b8(c) )
					# input()
'''

"""
# Résultats
x1 = randint(2**63, 2**64-1)
x2 = randint(2**63, 2**64-1)
diff = repr([
	'11101010','00000011','00000000',
	'11101001','11101001',
	'11101001','11101010','11101001'
])

'''
Différentiel pour la partie 1
00000000 00000000 00000000
11101010 00000011 00000000

Différentiel pour la partie 2
00000000 00000000
11101001 11101001

Différentiel pour la partie 3
00000000 00000000 00000000
00000000 00000000 11101001
10000100 10000001 00000000
11101001 11101010 00000000
11101001 11101010 11101001
'''
r1 = f_diff(x1, x1^diff, print_ascii=False)
r2 = f_diff(x2, x2^diff, print_ascii=True)

print('R1: ', colorize('     '.join([format(x, '08b') for x in splt(r1)])))
print('R2: ', colorize('     '.join([format(x, '08b') for x in splt(r2)])))

print(diff)
print(r1)

exit()


"""