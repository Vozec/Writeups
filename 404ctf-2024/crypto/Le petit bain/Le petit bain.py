charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!"

flag_enc = [charset.index(x) for x in "C_ef8K8rT83JC8I0fOPiN6P!liE03W2NXFh1viJCROAqXb6o"]
plain = [charset.index(x) for x in "404CTF{tHe_c"]

n = len(charset)

def f_inv(a,b,n,x):
	return (pow(a, -1, n) * (x - b)) % n


A = [(flag_enc[i+6]-flag_enc[i]) * pow(plain[i+6]-plain[i],-1,n) % n for i in range(6)]
B = [flag_enc[i] - A[i] * plain[i] % n for i in range(6)]

flag = ''

for i, x in enumerate(flag_enc):
	a = A[i%6]
	b = B[i%6]
	x = f_inv(a,b,n,x)
	flag += charset[x]

print(flag)

# 404CTF{tHe_c4fF31ne_MakE5_m3_StR0nG3r_th4n_y0u!}