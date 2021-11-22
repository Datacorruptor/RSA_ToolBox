import random

#prime number generation (p,q)
firstPrimes=[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
def genrandom(n):
	return 2*random.randint(2**(n-2),2**(n-1)-1)+1
	#return 2*random.randint(2**(n-2),2**(n-1)-1)+1
def getLprime(n):
	Found=False
	while not Found:
		Found=True
		Lprime=genrandom(n)
		for i in firstPrimes:
			if Lprime%i==0:
				Found=False
				break
	return Lprime
def getHprime(bits):
	Found=False
	while not Found:
		Found=True
		Hprime= getLprime(bits)
		n=Hprime-1
		s=0
		while n%2==0:
			s+=1
			n//=2
		t=n
		n=Hprime
		k=bits
		for i in range(k):
			a=random.randint(2,Hprime-2)
			x=pow(a,t,n)
			if x==1 or x==n-1:
				continue
			canBe=False
			for j in range(s-1):
				x=pow(x,2,n)
				if x == 1:
					Found=False
					break
				if x==n-1:
					canBe=True
					break
			if not canBe:
				Found=False
			if not Found:
				break
	return Hprime

#get RSA keypairs
def getRSA(bit):
	p,q=getHprime(bit//2),getHprime(bit//2)
	N=p*q 
	phi=(p-1)*(q-1)
	e=65537
	d=bezout(e,phi)[0]%phi
	return (e,d,N)

def rsa(m,e,N):
	return pow(m,e,N)
def rsaTenc(text,e,N):
	m = int_from_bytes(bytes(text,'ascii'))
	print("m="+str(m))
	return pow(m,e,N)
def rsaTdec(c,d,N):
	dec = pow(c,d,N)
	print("dec="+str(dec))
	try:
		return int_to_bytes(dec).decode("ASCII")
	except:
		return dec.to_bytes((dec.bit_length() + 7) // 8, 'little').decode("ASCII")
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')


#extended euclidian
def bezout(a, b):
    x, xx, y, yy = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x, xx = xx, x - xx*q
        y, yy = yy, y - yy*q
    return (x, y, a)

#known d attack
def pqfromd(e,d,N):
	while True:
		k=d*e-1
		g=random.randint(0,N)
		p=1
		while k %2==0:
			k=k//2
			x=pow(g,k,N)
			if x != 1:
				_,_,p=bezout(x-1,N)
				break
		if p!=1:
			return (p,N//p)

#small d attack
def getfract(a,b):
	fract=[]
	while b:
		next=a//b
		a,b=b,a%b
		fract.append(next)
	return fract
def getconv(fract):
	h=[0,1]
	k=[1,0]
	a=fract.copy()
	conv=[]
	for i in range(len(a)):
		h.append(a[i]*h[i+1]+h[i])
		k.append(a[i]*k[i+1]+k[i])
		conv.append((h[-1],k[-1]))
	return conv
def recoversmalld(e,N):
		fract=getfract(e,N)
		conv=getconv(fract)
		for i in conv:
			if(pow(pow(1337,i[1],N),e,N)==1337):
				return i[1]
		return "too big d"



e,d,N = getRSA(2048)
print((e,d,N))


