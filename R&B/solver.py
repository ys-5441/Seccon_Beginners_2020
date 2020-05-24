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

		

