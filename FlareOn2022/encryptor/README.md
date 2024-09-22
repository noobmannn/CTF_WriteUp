# encryptor

Challenge cho một file PE64 ``flareon.exe`` và một file ``SuspiciousFile.txt.Encrypted``

![image](https://github.com/user-attachments/assets/38d9f9f5-55d2-4d19-adcf-9afd912f5640)

Mở bằng IDA, lần theo chuỗi mặc định ``usage: flareon path [path ...]``, ta đến được hàm ``sub_4022A3`` với mã giả như dưới đây

```C
__int64 __fastcall MainHandl(int a1, const char **a2)
{
  HMODULE LibraryA; // rax
  FILE *v5; // rax
  unsigned int v6; // esi
  const char *v7; // r14
  int v8; // ebx
  FILE *src; // rdi
  char *v10; // r14
  FILE *ress; // rbx
  FILE *res2; // rax
  FILE *v13; // rax
  FILE *v14; // rax
  const char *v16; // [rsp+28h] [rbp-50h]
  __int64 Buf2[8]; // [rsp+36h] [rbp-42h] BYREF

  sub_402560();
  qmemcpy(Buf2, ".EncryptMe", 10);
  LibraryA = LoadLibraryA("advapi32");
  if ( !LibraryA )
    return (unsigned int)-1;
  SystemFunction036 = (BOOLEAN (__stdcall *)(PVOID, ULONG))GetProcAddress(LibraryA, "SystemFunction036");
  if ( !SystemFunction036 )
    return (unsigned int)-1;
  if ( a1 <= 1 )
  {
    v5 = (FILE *)off_404110(2i64);
    fputs("usage: flareon path [path ...]\n", v5);
    return (unsigned int)-1;
  }
  init_RSA();
  v6 = 0;
  while ( 1 )
  {
    v7 = *++a2;
    if ( !*a2 )
      break;
    v8 = strlen(*a2) - 10;
    if ( v8 > 0 && !memcmp(&v7[v8], Buf2, 0xAui64) )
    {
      src = fopen(v7, "rb");
      if ( src )
      {
        v10 = strdup(*a2);
        strcpy(&v10[v8], ".Encrypted");
        ress = fopen(v10, "rb");
        if ( !ress )
        {
          res2 = fopen(v10, "wb");
          ress = res2;
          if ( !res2 )
            goto LABEL_15;
          ++v6;
          maybeEnc(res2, src);
          v16 = *a2;
          v13 = (FILE *)off_404110(2i64);
          fprintf(v13, "%s\n", v16);
        }
        fclose(ress);
LABEL_15:
        fclose(src);
        free(v10);
      }
    }
  }
  v14 = (FILE *)off_404110(2i64);
  fprintf(v14, "%u File(s) Encrypted\n", v6);
  if ( v6 )
  {
    suss();
    return 0;
  }
  return v6;
}
```

Đọc qua mã giả, có thể tưởng tượng được luồng cơ bản của chương trình sẽ như sau: đọc file có định dạng ``.EncryptMe``, đưa qua hàm ``maybeEnc`` để mã hoá và ghi lại vào một file khác có cùng tên nhưng phần mở rộng là ``.Encrypted``, sau đó in ra số lượng file đã được mã hoá ở dưới.

Đầu tiên chương trình có ResolveAPI để lấy địa chỉ của ``SystemFunction036``, hàm này còn được gọi là ``RtlGenRandom``. Như đúng cái tên, hàm này tạo ra một Buffer ngẫu nhiên với độ dài theo yêu cầu của người tạo. Hàm này sẽ được sử dụng rất nhiều trong file.

Tiếp theo vào hàm ``Init_RSA``, ta có mã giả của nó như dưới đây

```C
__int64 init_RSA()
{
  __int64 p[17]; // [rsp+30h] [rbp-348h] BYREF
  __int64 q[17]; // [rsp+B8h] [rbp-2C0h] BYREF
  __int64 pSub1[17]; // [rsp+140h] [rbp-238h] BYREF
  __int64 qSub1[17]; // [rsp+1C8h] [rbp-1B0h] BYREF
  __int64 pSub1MulqSub1[17]; // [rsp+250h] [rbp-128h] BYREF
  __int64 v6[17]; // [rsp+2D8h] [rbp-A0h] BYREF

  do
    GenRandomNumber64Byte(p);
  while ( !(unsigned int)maybeCheckPrime(p) );  // p
  do
    GenRandomNumber64Byte(q);
  while ( !(unsigned int)maybeCheckPrime(q) );  // q
  multiple(pMulq, (unsigned __int64 *)p, (unsigned __int64 *)q);// p * q
  sub1((unsigned __int64 *)pSub1, (unsigned __int64 *)p);// p - 1
  sub1((unsigned __int64 *)qSub1, (unsigned __int64 *)q);// q - 1
  multiple(pSub1MulqSub1, (unsigned __int64 *)pSub1, (unsigned __int64 *)qSub1);// phi = (p - 1) * (q - 1)
  find_d(d, d, pSub1MulqSub1);                  // e = 0x10001
                                                // d = inverse_mod(0x10001, phi)
  return pow_modular(sus2dat, v6, &RSA_E, (__int64)&unkdat);// sus2dat = pow(v6, e, unkdat)
}
```

Bằng cách phỏng đoán và debug thử liên tục, mình có thể sửa lại tên các hàm như trên và hiểu được chức năng của nó: Tạo hai số nguyên tố ngẫu nhiên 64 byte như trên, sau đó tính các giá trị cần thiết cho thuật toán RSA, bao gồm n, phi, d, giá trị e của thuật toán được mặc định là ``0x10001``

Sau khi khởi tạo các giá trị cần thiết của RSA, ta phân tích tiếp hàm ``maybeEnc``

```C
int __fastcall maybeEnc(FILE *res2, FILE *src)
{
  __int64 v4; // rcx
  _DWORD *v5; // rdi
  __int128 *v6; // rdi
  __int64 i; // rcx
  _DWORD Chacha20_Key_Nonce_RSA_Encrypt[34]; // [rsp+20h] [rbp+0h] BYREF
  __int128 key32byterandom[2]; // [rsp+A8h] [rbp+88h] BYREF
  __int128 maybenonce[9]; // [rsp+C8h] [rbp+A8h] BYREF

  v4 = 34i64;
  v5 = Chacha20_Key_Nonce_RSA_Encrypt;
  while ( v4 )
  {
    *v5++ = 0;
    --v4;
  }
  v6 = key32byterandom;
  for ( i = 34i64; i; --i )
  {
    *(_DWORD *)v6 = 0;
    v6 = (__int128 *)((char *)v6 + 4);
  }
  SystemFunction036(key32byterandom, 0x20u);    // gen32bytekeyrand
  SystemFunction036((char *)maybenonce + 4, 0xCu);// gen12bytenonce
  chacha20(res2, src, key32byterandom, maybenonce);// counter = 0
  pow_modular(Chacha20_Key_Nonce_RSA_Encrypt, key32byterandom, d, (__int64)pMulq);// v9 = pow(key_nonce, d, pMulq)
  fprintfsusss(res2, (__int64)&unkdat);
  putc('\n', res2);
  fprintfsusss(res2, (__int64)pMulq);
  putc('\n', res2);
  fprintfsusss(res2, (__int64)sus2dat);
  putc('\n', res2);
  fprintfsusss(res2, (__int64)Chacha20_Key_Nonce_RSA_Encrypt);
  return putc('\n', res2);
}
```

Ở đây chương trình sử dụng ``SystemFunction036`` để gen ra một mảng 32 byte và 1 mảng 12 byte khác đều ngẫu nhiên, sau đó truyền hai mảng này vào hàm ``sub_4020F0``

![image](https://github.com/user-attachments/assets/078ef61e-9380-49dc-b7c7-2dbbd217edcc)

Hàm này khai báo một chuối mặc định là ``expand 32-byte k`` nên mình đoán thuật toán mã hoá được sử dụng là chacha20. Từ đây hàm này mã hoá toàn bộ data của file được đọc bằng chacha20 với key là mảng 32 byte ngẫu nhiên và nonce là mảng 12 byte ngẫu nhiên được truyền vào. Sau khi mã hoá xong thì ghi vào file ``.Encrypted``

Lúc này khi debug ta có thể thấy: mảng key 32 byte cùng với mảng 12 byte nonce với 4 byte 0 chèn vào ở giữa tạo thành một dải data 48 byte, và dải data này được mã hoá bằng RSA thông qua lệnh ``pow_modular(Chacha20_Key_Nonce_RSA_Encrypt, key32byterandom, d, (__int64)pMulq)`` với số mũ được dùng mã hoá là giá trị ``d``

Sau đó chương trình sẽ add các giá trị bao gồm một dải data cố định, giá trị n của RSA, một giải data gì đó khác và giá trị  key_nonce được mã hoá bằng RSA

```C
  fprintfsusss(res2, (__int64)&unkdat);
  putc('\n', res2);
  fprintfsusss(res2, (__int64)pMulq);
  putc('\n', res2);
  fprintfsusss(res2, (__int64)sus2dat);
  putc('\n', res2);
  fprintfsusss(res2, (__int64)Chacha20_Key_Nonce_RSA_Encrypt);
  return putc('\n', res2);
```

Xem file ``SuspiciousFile.txt.Encrypted``, ta có thể lấy được giá trị n và key_nonce bị mã hoá bằng RSA

![image](https://github.com/user-attachments/assets/4b2318a8-6cf0-4e96-b675-9c1187e849c5)

Từ đó ta viết được Script

```python
from Crypto.Cipher import ChaCha20

unkdat = 0x9f18776bd3e78835b5ea24259706d89cbe7b5a79010afb524609efada04d0d71170a83c853525888c942e0dd1988251dfdb3cd85e95ce22a5712fb5e235dc5b6ffa3316b54166c55dd842101b1d77a41fdcc08a43019c218a8f8274e8164be2e857680c2b11554b8d593c2f13af2704e85847f80a1fc01b9906e22baba2f82a1
n = 0xdc425c720400e05a92eeb68d0313c84a978cbcf47474cbd9635eb353af864ea46221546a0f4d09aaa0885113e31db53b565c169c3606a241b569912a9bf95c91afbc04528431fdcee6044781fbc8629b06f99a11b99c05836e47638bbd07a232c658129aeb094ddaf4c3ad34563ee926a87123bc669f71eb6097e77c188b9bc9
sus2dat = 0x8e678f043c0d8b8d3dff39b28ce9974ff7d4162473080b54eefaa6decb8827717c6b24edfff7063375b6588acf8eca35c2033ef8ebe721436de6f2f66569b03df8c5861a68e57118c9f854b2e62ca9871f7207fafa96aceba11ffd37b6c4dbf95b256184983bad407c7973e84b23cd22579dd25bf4c1a03734d1a7b0dfdcfd44
Chacha20_Key_Nonce_RSA_Encrypt = 0x5a04e95cd0e9bf0c8cdda2cbb0f50e7db8c89af791b4e88fd657237c1be4e6599bc4c80fd81bdb007e43743020a245d5f87df1c23c4d129b659f90ece2a5c22df1b60273741bf3694dd809d2c485030afdc6268431b2287c597239a8e922eb31174efcae47ea47104bc901cea0abb2cc9ef974d974f135ab1f4899946428184c
enc = bytes.fromhex('7F 8A FA 63 65 9C 5E F6 9E B9 C3 DC 13 E8 B2 31 3A 8F E3 6D 94 86 34 21 46 2B 6F E8 AD 30 8D 2A 79 E8 EA 7B 66 09 D8 D0 58 02 3D 97 14 6B F2 AA 60 85 06 48 4D 97 0E 71 EA 82 06 35 BA 4B FC 51 8F 06 E4 AD 69 2B E6 25 5B')

e = 0x10001
print(hex(pow(Chacha20_Key_Nonce_RSA_Encrypt, e, n)))
sus = bytes.fromhex(hex(pow(Chacha20_Key_Nonce_RSA_Encrypt, e, n)).lstrip('0x'))[::-1]
key, nonce = sus.split(b'\00' * 4)
cipher = ChaCha20.new(key=key, nonce=nonce)
print(cipher.decrypt(enc))
```

Ta lấy được flag như dưới

```
0x958f924dfe4033c80ffc490200000000989b32381e5715b4a89a87b150a5d528c943a775e7a2240542fc392aa197b001
b'Hello!\n\nThe flag is:\n\nR$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flare-on.com\n'
```

# Flag

``R$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flare-on.com``
