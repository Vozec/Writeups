charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!"
enc_flag = "-4-c57T5fUq9UdO0lOqiMqS4Hy0lqM4ekq-0vqwiNoqzUq5O9tyYoUq2_"

def f(a,b,n,x):
	return (a*x+b)%n

def f_inv(a,b,n,x):
	for k in range(255):
		if f(a,b,n,k) == x:
			return k
	return 0

def encrypt(message,a,b,n):
	encrypted = ""
	for char in message:
		x = charset.index(char)
		x = f(a,b,n,x)
		encrypted += charset[x]
	return encrypted

def decrypt(message,a,b,n):
	decrypted = ""
	for char in message:
		x = charset.index(char)
		x = f_inv(a,b,n,x)
		decrypted += charset[x]
	return decrypted


def get_ab():
	for a in range(2, n-1):
		for b in range(1, n-1):
			enc = encrypt(plain, a, b, n)
			if enc == enc_flag[:len(plain)]:
				return a, b
	return 0, 0

plain = "404CTF{"
n = len(charset)

a, b = get_ab()
print(decrypt(enc_flag, a, b, n))

# 404CTF{Th3_r3vEnGE_1S_c0minG_S0oN_4nD_w1Ll_b3_TErRiBl3_!}