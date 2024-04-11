# Run this script in https://sagecell.sagemath.org/
from sage.all import *

b = Mod(37, 0x1FFFFFFFFFFFFFFF)
# check = [0x144E5D523792D5BA ^ 0x11DB2A3F, 0x74673B80C8E5901 ^ 0x30836D0F, 0x1602C4A2E244D043 ^ 0xAD48145, 0x089FD614A79A8273 ^ 0x1ECB02BB]
check = [0x144e5d522649ff85, 0x74673b83c0d340e, 0x1602c4a2e8905106, 0x89fd614b95180c8]
flag = b''
for i in check:
    res = int(discrete_log(i, b))
    by = res.to_bytes(7, byteorder='little')
    flag += by
print(flag.decode())
# gigem{i_<3_m3rs3nn3_pr1m35!}



# def enc(a1):
#     v1 = 0x25
#     v3 = 1
#     while a1:
#         if a1 & 1 != 0:
#             tmp = v3 * v1
#             v3 = tmp & 0xFFFFFFFFFFFFFFFF
#             rdx = (tmp >> 64) << 3
#             rax = v3 >> 61
#             rdx = rdx | rax
#             v3 = (v3 << 3) & 0xFFFFFFFFFFFFFFFF
#             v3 = v3 >> 3
#             v3 += rdx
#             a = (v3 - 0x1FFFFFFFFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
#             if v3 >= a:
#                 v3 = a
#             v3 = v3 & 0xFFFFFFFFFFFFFFFF
#         tmp = v1 * v1
#         v1 = tmp & 0xFFFFFFFFFFFFFFFF
#         rdx = (tmp >> 64) << 3
#         rax = v1 >> 61
#         rdx = rdx | rax
#         v1 = (v1 << 3) & 0xFFFFFFFFFFFFFFFF
#         v1 = v1 >> 3
#         v1 += rdx
#         a = (v1 - 0x1FFFFFFFFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
#         if v1 >= a:
#             v1 = a
#         v1 = v1 & 0xFFFFFFFFFFFFFFFF
#         a1 = a1 >> 1
#     return v3

# char = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=<>,./{[]\|~:;?"\''
# for c in char:
#     flag = 'gigem{'
#     flag += c
#     ascii_codes = [ord(char) for char in flag][::-1]
#     hex_str = ''.join([format(code, '02x') for code in ascii_codes])
#     hex_result = int(hex_str, 16)
#     if enc(hex_result) == 0x144E5D523792D5BA ^ 0x0000000011DB2A3F:
#         print(flag)
#         break
