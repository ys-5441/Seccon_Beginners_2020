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


def IsPadding_OK(c_t, Dec_ci, m_prime, c_prev_prime):
	
	attempt_byte = "\x11" * (block_size-m_prime) + chr(c_prev_prime)
	adjusted_bytes = ""
	for c in Dec_ci:
		adjusted_bytes += chr(ord(c) ^ m_prime)

	content = attempt_byte.encode('hex') + adjusted_bytes.encode('hex') + c_t
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
	c_t = cipher_block[0].encode('hex')
	c_p = cipher_block[1].encode('hex')
	cipher_block.pop(0)

	m_prime = 1
	c_prev_prime = 0
	m = Dec_ci = ""
	while True:
		if IsPadding_OK(c_t, Dec_ci, m_prime, c_prev_prime):
			print "0x{:02x}: ".format(c_prev_prime) + "{:02x}".format(m_prime) * m_prime
			m += chr(c_prev_prime ^ m_prime ^ ord(c_p.decode('hex')[::-1][m_prime-1]))
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
	print "Dec(c%d): %s" % (len(cipher_block), Dec_ci.encode('hex').zfill(block_size*2))
	print "m%d: %s" % (len(cipher_block), repr(m[::-1]))
	plain_text = m[::-1] + plain_text
	print "plain_text:", repr("*" * (len(cipher_text)-len(plain_text)-block_size) + plain_text) + '\n'
