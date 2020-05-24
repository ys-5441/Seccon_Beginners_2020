from pwn import *
from Crypto.Util.number import *
import sympy
from functools import reduce
from operator import mul
from itertools import combinations
import sys

io = remote("rsacalc.quals.beginners.seccon.jp", 10001)
#io = remote("localhost", 10001)
#ctf4b{SIgn_n33ds_P4d&H4sh}

def Get_N():
	recv_m = io.recvuntil("3) Exit").strip()
	print("recv_m: {}".format(recv_m))
	N = recv_m.split("\n")[0].split(":")[1].strip()
	print("N: {}".format(N))
	return int(N)


def Sign(data):
	io.sendline("1")
	print(io.recvuntil("data>"))
	io.sendline(data)
	recv_m = io.recvline().strip()
	print("recv_m: {}".format(recv_m))
	sig = recv_m.split()[1].strip()
	print("sig:{}".format(sig))
	print(io.recvuntil("3) Exit"))
	return sig


def Exec(data, sig):
	io.sendline("2")
	print(io.recvuntil("data>"))
	io.sendline(data)
	print(io.recvuntil("signature>"))
	io.sendline(sig)
	recv_m = io.recvline()
	print(recv_m)
	if "Error" in recv_m or "Invalid" in recv_m:
		io.close()
		return
	print(io.recvline())
	
N = Get_N()

payload  =  "1337,F"
#print(sympy.factorint(bytes_to_long(payload)))
#Factors: factors of payload 
Factors = [1081919446939, 2*5*5]

X = []
"""
for tem in combinations(range(len(Factors)), 2):
	Idx_list  = [ i for i in range(len(Factors)) if i not in  tem]
	num_1 = Factors[tem[0]] * Factors[tem[1]]
	num_2 = reduce(mul, [Cand[i] for i in Idx_list ] )
	X.append((num_1,  num_2) )
"""

Sig = []

for i in range(len(Factors)):
	data = long_to_bytes(Factors[i])
	sig = Sign(data)
	Sig.append(int(sig, 16))
#print(Sig)
send_sig = hex(reduce(mul, Sig)%N)[2:]
assert send_sig < 0 or send_sig >= N
#print("send_sig: {}".format(send_sig))
Exec(payload, send_sig)
io.close()
