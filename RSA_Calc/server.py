from Crypto.Util.number import *
#from params import p, q, flag
import binascii
import sys
import signal
import traceback
p = 121927065661948314886012046118374173561666942358502532317254322005541135858307319977020939353567498123147060974803233739883096761392450151779380688177394690737979821960839477635847277249980883185897093802479120194242107771138632309852915809800594416545268355422219163881158279125860564241888102011240209357051
q = 169459909302278086098623180652473966362113109055882587241548685061676127674131713412757719508480496276393205379507005801694109949761538558878896994084715820058995131532722788341918748478157085023857920655710952157974191523840118249199562256273394650566521931863455432303727339499437735045426889564665983931689
flg = "Test"
N = p * q
e = 65537
d = inverse(e, (p-1)*(q-1))


def input(prompt=''):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return sys.stdin.buffer.readline().strip()

def menu():
    sys.stdout.write('''----------
1) Sign
2) Exec
3) Exit
''')
    try:
        sys.stdout.write('> ')
        sys.stdout.flush()
        return int(sys.stdin.readline().strip())
    except:
        return 3


def cmd_sign():
    data = input('data> ')
    if len(data) > 256:
        sys.stdout.write('Too long\n')
        return

    if b'F' in data or b'1337' in data:
        sys.stdout.write('Error\n')
        return

    signature = pow(bytes_to_long(data), d, N)
    sys.stdout.write('Signature: {}\n'.format(binascii.hexlify(long_to_bytes(signature)).decode()))

def cmd_exec():
    data = input('data> ')
    signature = int(input('signature> '), 16)

    if signature < 0 or signature >= N:
        sys.stdout.write('Invalid signature\n')
        return

    check = long_to_bytes(pow(signature, e, N))
    if data != check:
        sys.stdout.write('Invalid signature\n')
        return

    chunks = data.split(b',')
    stack = []
    for c in chunks:
	print("c: {}".format(c))
        if c == b'+':
            stack.append(stack.pop() + stack.pop())
        elif c == b'-':
            stack.append(stack.pop() - stack.pop())
        elif c == b'*':
            stack.append(stack.pop() * stack.pop())
        elif c == b'/':
            stack.append(stack.pop() / stack.pop())
        elif c == b'F':
            val = stack.pop()
            if val == 1337:
                sys.stdout.write(flag + '\n')
        else:
            stack.append(int(c))

    sys.stdout.write('Answer: {}\n'.format(int(stack.pop())))


def main():
    sys.stdout.write('N: {}\n'.format(N))
    while True:
        try:
            command = menu()
            if command == 1:
                cmd_sign()
            if command == 2:
                cmd_exec()
            elif command == 3:
                break
        except:
            #sys.stdout.write('Error\n')
            sys.stdout.write(traceback.format_exc())
            break


if __name__ == '__main__':
    signal.alarm(60)
    main()
