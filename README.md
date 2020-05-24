# Seccon_Beginners_2020 Writeup

m1z0r3の一員で参加してきたのでいくつかWriteup上げてみます。Crypto問を主に解いたのでそれについて。

解いた問題・・RSA Calc, Encrypter

他のメンバーが先に解いて後追いして解いた問題・・R&B, Noisy equations



### R&D

唯一Beginnersっぽいと感じた問題

"R"または"B"というformatにしたがってrot-13とbase64によるエンコードを繰り返して先頭に"R"または"B"を加えているだけ。なので先頭がどちらかを見ながらrot-13とbase64デコードを繰り返すだけ。

```python
from base64 import b64decode
import codecs
with open("encoded_flag", "r") as f:
	ct = f.read()
idx = 0
ct_tem = ct
flag = ""

while True:
	if ct_tem[0] == "R":
		ct_tem = codecs.decode(ct_tem[1:], "rot-13")
	else :
		ct_tem = b64decode(ct_tem[1:])
	print(ct_tem)
print(flag)
```

Flag: `ctf4b{rot_base_rot_base_rot_base_base}`



### Noisy equations

44次元の連立方程式の問題。

coeffs = [x11, x12, .., x1n], [x21, x22, .. ,xnn] , .. ], answers = [a1, a2, .., an], flag = [f0, f1, .., fn]とおくと、問題の式は次のようになる。Aはseedを加えた後の `getrandbits(L)` の値。


$$
\begin{pmatrix}a_{1}\\a_{2}\\\vdots\\a_{n}\end{pmatrix} = \begin{pmatrix} x_{11} & x_{12} &..& x_{1n} &A\\ 
\vdots & \vdots& \ddots& \vdots&\vdots\\
x_{n1} &x _{n2}&..& x_{nn} &A\end{pmatrix}\begin{pmatrix}f_{1}\\f_{2}\\\vdots\\f_{n}\end{pmatrix}
$$
Aが邪魔なため、もう一度サーバからcoeffs, answersを受け取り、差分を取る。

差分を取った後の $a,x$ を $ad, xd$ とおくと

 


$$
\begin{pmatrix}ad_{1}\\ad_{2}\\\vdots\\ad_{n}\end{pmatrix} = \begin{pmatrix} xd_{11} & xd_{12} &..& xd_{1n} \\ 
\vdots & \vdots& \ddots& \vdots\\
xd_{n1} &xd_{n2}&..& xd_{nn} \end{pmatrix}\begin{pmatrix}f_{1}\\f_{2}\\\vdots\\f_{n}\end{pmatrix}
$$
となり、簡単に計算できる形になる。



初めこれをsympyでローカルで解こうとしてみたらとんでもなく時間がかかるため（冷静に考えて値と次元数がこれだけ多いと厳しい..）、sageで次のようにして解いた。

```sage
Xd = matrix([ [xd11, xd12, .., xd1n], [xd21, xd22, .. ,xdnn] , .. ])
Ad = vector([ad1, ad2, .., adn])
F = Xd.solve_right(Ad)
```

あとはFの値を全て文字に変換すればFlagが得られる。

Flag: `ctf4b{r4nd0m_533d_15_n3c3554ry_f0r_53cur17y}`

※他の方のWriteupをみているとnumpyでfloat64型を使えばローカルで問題なくできるようです。



### RSA_Calc

RSA署名の問題。
server.pyを読むと、"1337,F"という文字列の署名が得られれば勝ちなのが分かる。

しかし、当然その1337やFが文字列に入っていると署名をもらえない。

そこで、"1337,F"を素因数分解してそれぞれを署名してもらい、掛け合わせれば"1337,F"の署名が手に入る。

なぜこれでできるのかというと、次のことが成り立つから。

$X= a*b$とすると、
$$
(a^d\;mod \;N) * (b^d \;mod \;N) \\
= a*b ^d \;mod \;N\\
= X^d \;mod \;N
$$
実装したsolver.pyは以下。

```python
from pwn import *
from Crypto.Util.number import *
import sympy
from functools import reduce
from operator import mul
from itertools import combinations
import sys

io = remote("rsacalc.quals.beginners.seccon.jp", 10001)
#io = remote("localhost", 10001)

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

```



Flag: `ctf4b{SIgn_n33ds_P4d&H4sh}`

2019 VolgaCTF Blindの類題ですね。



### Encrypter



最初よく分からなかったが、メンバーの教えでPadding Oracleだと気づき、実装しました。

`Decrypt`にbase64デコードに失敗するものや、16バイト長になっていないものを送ると`error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length`

と表示され、パディング処理に失敗すると`error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt`と表示されるっぽい。

なのでサーバ側ではAESのCBCモードで暗号/復号を行っていると仮定して、`Encrypted Flag`で暗号化されたフラグを手に入れ、Padding Oracle をする。

http://rintaro.hateblo.jp/entry/2017/12/31/174327の記事を参考にさせて頂きました。

solverは以下（Python2系）



```python
# -*- coding: utf-8 -*-
import socket
from tqdm import tqdm
import requests
import json
import time
from base64 import b64decode, b64encode
from Crypto.Util.number import isPrime, bytes_to_long, long_to_bytes
import sympy
from binascii import hexlify , unhexlify
from tqdm import tqdm
import sys

block_size = 16


def IsPadding_OK(c_target, Dec_ci, m_prime, c_prev_prime):
	
	attempt_byte = "\x11" * (block_size-m_prime) + chr(c_prev_prime)
	adjusted_bytes = ""
	for c in Dec_ci:
		adjusted_bytes += chr(ord(c) ^ m_prime)

	content = attempt_byte.encode('hex') + adjusted_bytes.encode('hex') + c_target
	#print(content)
	payload = {"mode": "decrypt", "content": content.decode("hex").encode("base64")}
	#print("payload: {}".format(payload))
	r = requests.post("http://encrypter.quals.beginners.seccon.jp/encrypt.php", data = json.dumps(payload))
	#res = hexlify(b64decode(r.json()["result"]))
	res = r.content
	#print("res: {}".format(res))
	if "ok" in res.decode():
	    print("res: {}".format(res))
	    return True
	else:
	    return False


	enc_flag = "bezb4nnncZqltGeA46QkrHbHHo/pUh3M+Zu/WxJE+wdglDFot1jmmxNycOKpoMSZTxyJxVMkKF3rBeCZrT6Ozw=="
	cipher_text = b64decode(enc_flag).encode("hex")
	cipher_text = cipher_text.zfill(len(cipher_text) + len(cipher_text) % block_size*2).decode('hex')
	print("cipher_text: {}".format(cipher_text))
	

	cipher_block = [cipher_text[i: i+block_size] for i in range(0, len(cipher_text), block_size)]
	cipher_block.reverse()
	plain_text = ""
	print("cipher_block: {}".format(cipher_block))

	for i in tqdm(range(len(cipher_block)-1)):
		c_target = cipher_block[0].encode('hex')
		c_prev = cipher_block[1].encode('hex')

		print ("c_prev:", c_prev)
		print ("c_target:", c_target)
		cipher_block.pop(0)

		m_prime = 1
		c_prev_prime = 0
		m = Dec_ci = ""
		while True:
			if IsPadding_OK(c_target, Dec_ci, m_prime, c_prev_prime):
				print "0x{:02x}: ".format(c_prev_prime) + "{:02x}".format(m_prime) * m_prime
				m += chr(c_prev_prime ^ m_prime ^ ord(c_prev.decode('hex')[::-1][m_prime-1]))
				Dec_ci = chr(c_prev_prime ^ m_prime) + Dec_ci
				m_prime += 1
				c_prev_prime = 0
				if m_prime <= block_size:
					continue
				break
			c_prev_prime += 1
			if c_prev_prime > 0xff:
				print "[-] Not Found"
				break
		print "[+] Dec(c%d): %s" % (len(cipher_block), Dec_ci.encode('hex').zfill(block_size*2))
		print "[+] m%d: %s" % (len(cipher_block), repr(m[::-1]))
		plain_text = m[::-1] + plain_text
		print "[+] plain_text:", repr("*" * (len(cipher_text)-len(plain_text)-block_size) + plain_text) + '\n'

if __name__ == "__main__":
	main()
```

Flag: `ctf4b{p4d0racle_1s_als0_u5eful_f0r_3ncrypt10n}`









