import os
import warnings
os.environ['PWNLIB_NOTERM'] = '1'
warnings.filterwarnings("ignore", category=DeprecationWarning) 

from pwn import *
from random import randint

from fastecdsa.curve import Curve
from fastecdsa.point import Point


context.log_level = 'critical'

class client:
	def __init__(self, ip, port, debug=False, E=None, timeout=60) -> None:
		self.ip = ip
		self.port = port
		self.debug = debug
		self.E = E
		if self.debug:
			self.io = process(['python3', 'main.py'], timeout=timeout)
		else:
			self.io = remote(self.ip, int(self.port), timeout=timeout)

	def shell(self):
		self.io.interactive()

	def read_rsa(self) -> list[int, int]:
		self.io.recvuntil(b'n=')
		n = int(self.io.recvline().strip().decode(),16)
		self.io.recvuntil(b'e=')
		e = int(self.io.recvline().strip().decode(),16)
		self.n = n
		self.e = e
		return self.n, self.e

	def send_seed(self, seed: list, d: int, n: int) -> None:
		for point in seed:
			x, y = point.x, point.y
			self.send_point(x, y, d, n)

	def send_point(self, x: int, y: int, d, n) -> None:
		def sign_RSA(m, d, n):
			assert 0 < m < n
			return int(pow(int(m), d, n))
		self.io.recvuntil(b'x:')
		self.io.sendline(str(sign_RSA(x, d, n)).encode())
		self.io.recvuntil(b'y:')
		self.io.sendline(str(sign_RSA(y, d, n)).encode())

	def read_challenge(self):
		self.io.recvuntil(b'Decrypt this to get access to the reserved part:')
		self.io.recvline()
		data = self.io.recvline().strip().decode()
		enc = eval(data.replace(': 1)',', E)').replace(':',',').replace('(', 'Point('))
		self.enc = enc
		return self.enc

	def read_public(self):
		self.io.recvuntil(b'Encrypting the test, please be patient')
		self.io.recvline()
		data = self.io.recvline().strip().decode()[1:-1]		
		data = data.split(',')
		data = [eval('Point(%s, E)'%(','.join(x.strip()[1:-1].split(':')[:2]))) for x in data]
		self.pub = data
		return self.pub

	def submit(self, solution):
		self.io.recvuntil(b'Your guess: ')		
		self.io.sendline(str(solution).encode())
		res = self.io.recvline()
		print(res)
		return res

a=0x237fb0a7a54cdfdd0814e5d1e8bab008594ecb4f1df32aebb4c5f4623160fafca0d6f6666ebb52328c59f78fde406a010f8799867d0f8b1837ebabc0f81551f3
b=0x7c6a2571f182fe4dafb728bf772ba8fe2b2dc44693c2008c136a00ddccd66e77169214a8b9263082b2d10bce7462984b140d1a6de7d7ef73148192e196acda59
prime=0xf19b2b57d34cb8d373bf18edce5e601292d620ccb534a011c59752a57f0294d056ce82fd1ef7e0cbae81e215845bcccce5582852c8b3c24130c14f4cedadf41b
size = 300

c = client('challenges.404ctf.fr', 30593, debug=False, timeout=None)
n, e = c.read_rsa()

# p, q, _ = Wiener(e, n)
p, q = [109663834623511447758312320062014978566368665084313528054667813574154140294581,
		115388449048683835279716983021469759400051127751886505916868550721259514357081]

d = pow(e, -1, (p-1)*(q-1))
assert p*q == n and pow(pow(0xdeadbeef, d, n),e, n) == 0xdeadbeef

G = [
	9320465191800756301270265396841294261738836730587197934485324200424335811058797481516750499561167781393996007457109406985854266737409049549233990441328696,
	1675596552838099315823906543349230361300288772174641249979830042980461033785586902698553232202364020888992002354170377344327027349222075707638452394140305
]

E = Curve(
	name = "Custom Curve",
	p = prime,
	a = a,
	b = b,
	q = n,
	gx = G[0],
	gy = G[1]
)

c.E = E

SEED = [
	Point(
		9581412612102760264742576700206475538679013169157761912109690480361469766847393302185823508701383367091761075948593689795088648984601346947912693709666701,
		491383869981262217540091247345250754561203015163815997088196604690808362859579966687104552116106590050162495513760495142076411985463269086566079613587468,
		E	
	),
	Point(
		3208770585151612544266706135933659912687233366832394522259352846029150718292568098363116621836117143909439045769435231221713580308613922629936956286037258,
		9663471900511767308160453901591243064545687892667150675511761526849693194769727218066702462424833481402139907297096451395966523336412318928725141210413164,
		E	
	),
	Point(
		8425226996198045248181181534132682685624818434864803918180640084567371023091283755411523604089757984954964493031598033242230304277316007910663622669738518,
		11451028332294678511423495832471070796048270939843720768587959933974009330943298306955528238850340064276617450438163745220821281051361676053452915702655433,
		E	
	)
]

target_sum = SEED[0] + SEED[1] + SEED[2]

def find_triplet_v2(points, target):
	seen = set()
	count = 0  
	for i, a in enumerate(points):
		complement = target - a
		for b in points[i+1:]:
			if str(complement - b) in seen:
				count += 1
		seen.add(str(a))
	return '1' if count == 98 else '0'

c.send_seed(seed=SEED, d=d, n=n)
pub = c.read_public()
enc = c.read_challenge()

# enc = eval(open('./save/ct.txt', 'r').read().replace(': 1)',',E)').replace(':',',').replace('(', 'Point('))

print('Starting')

import time
before = time.time()

results = ''
for groupe in enc:
	results += find_triplet_v2(groupe, target_sum)
	print(results)

# with concurrent.futures.ThreadPoolExecutor(max_workers=(48//16)) as executor:
# 	futures = []
# 	for groupe in enc:
# 		thread = executor.submit(find_triplet_v2, groupe, target_sum)
# 		futures.append(thread)
# 	results = ''.join([future.result() for future in concurrent.futures.as_completed(futures)])

print(time.time() - before)

print(results)
print(int(results, 2))

c.submit(solution = int(results, 2))
c.shell()

"""
Bureau python3 RSAlade-tomatECC-oigNPon_v2.py 
[] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/vozec/.cache/.pwntools-cache-3.11/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[] You have the latest version of Pwntools (4.12.0)

Starting
0
01
011
0110
01101
011010
0110101
01101011
011010111
0110101111
01101011111
011010111110
0110101111100
01101011111001
011010111110010
0110101111100100
01101011111001001
011010111110010010
0110101111100100100
01101011111001001001
011010111110010010011
0110101111100100100111
01101011111001001001111
011010111110010010011111
0110101111100100100111110
01101011111001001001111101
011010111110010010011111011
0110101111100100100111110111
01101011111001001001111101111
011010111110010010011111011110
0110101111100100100111110111100
01101011111001001001111101111001
011010111110010010011111011110011
0110101111100100100111110111100111
01101011111001001001111101111001111
011010111110010010011111011110011110
0110101111100100100111110111100111100
01101011111001001001111101111001111001
011010111110010010011111011110011110011
0110101111100100100111110111100111100110
01101011111001001001111101111001111001101
011010111110010010011111011110011110011010
0110101111100100100111110111100111100110100
01101011111001001001111101111001111001101000
011010111110010010011111011110011110011010000
0110101111100100100111110111100111100110100001
01101011111001001001111101111001111001101000010
011010111110010010011111011110011110011010000100
46.597017765045166
011010111110010010011111011110011110011010000100
118629672281732
b'Welcome back. 404CTF{Une_p1nc33_d3_53l_37_un_peu_d3_p0ivr3}\n'
"""