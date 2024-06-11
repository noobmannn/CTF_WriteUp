import ctypes
from arc4 import ARC4

with open('flag', 'rb') as f:
    data = f.read()

dotText = data[0x1060:0x1227]
dotData = data[0x4020:0x4093]
dotRodata = data[0x2000:0x2007]
rightSeed = 0
for i in range(0, 0xFFFF):    
    seed = i
    LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
    LIBC.srand(seed)
    v4 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = ''
    for i in range(16):
        key += v4[LIBC.rand() % 62]
    arc4 = ARC4(key.encode())
    cipher = arc4.encrypt(bytes(dotText))
    op = cipher[0:5]
    # b'\x31\xed\x49\x89\xd1': opcode của xor ebp, ebp và mov r9, rdx, hai lệnh asm đầu tiên của hàm _start trong file ELF
    # b'\xf3\x0f\x1e\xfa\x55': opcode của endbr64 và push rbp, hai lệnh đầu tiên của mỗi hàm cơ bản bình thường
    if op == b'\xf3\x0f\x1e\xfa\x55' or op == b'\x31\xed\x49\x89\xd1':
        print('Key RC4: ', key)
        print('Opcode Header: ', op)
        print('Seed: ', hex(seed))
        print('Cipher .text: ', cipher)
        rightSeed = seed
        break

# seed là 0x13B6
# phải chạy bằng python của linux
