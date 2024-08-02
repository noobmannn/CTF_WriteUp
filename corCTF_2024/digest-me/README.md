# digest-me

Chal cho một file ELF64

![image](https://github.com/user-attachments/assets/1c70fc81-867b-4035-a8a0-196a1db634b0)

Chạy thử thì chương trình yêu cầu người dùng nhập flag, sai thì phải nhập lại cho đến khi nhập đúng

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ./digestme
Welcome!
Please enter the flag here: 
corctf{aaaaaaaaaa}
Try again: 

```

### Tổng quan

Mở file bằng IDA thì chương trình quá to nên không thể gen ra mã giả được :((

![image](https://github.com/user-attachments/assets/c9c4dde4-0d6b-4ee0-a263-a48ef08696a3)

Chuyển sang dạng text thì ta thấy một đoạn code asm rất dài tận 300000 dòng :((

![image](https://github.com/user-attachments/assets/81874318-585f-4172-81d8-63f2036e453a)

Trước mắt mình sẽ tạm thời nop đi đoạn code siêu dài trên để xem qua mã giả của chương trình, và sau khi nop đi ta có đoạn mã giả như sau:

```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _BYTE *v3; // r15
  size_t v4; // rax
  int v5; // esi
  char *v6; // rdi
  _BYTE *v7; // r9
  const unsigned __int16 *v8; // r10
  _BYTE *v9; // rax
  int v10; // ecx
  int v11; // edx
  __int64 i; // rcx
  __int64 v13; // rsi
  __int64 v14; // rcx
  int v15; // r9d
  int v16; // eax
  unsigned int v17; // r8d
  __int64 j; // rax
  const unsigned __int16 **v20; // [rsp+0h] [rbp-4C8h]
  _QWORD v21[2]; // [rsp+20h] [rbp-4A8h]
  char v22[16]; // [rsp+30h] [rbp-498h] BYREF
  _OWORD v23[5]; // [rsp+40h] [rbp-488h] BYREF
  int v24; // [rsp+90h] [rbp-438h]
  char s[1000]; // [rsp+A0h] [rbp-428h] BYREF

  puts("Welcome!\nPlease enter the flag here: ");
  v3 = calloc(1uLL, 0x186A0uLL);
  v20 = __ctype_b_loc();
  while ( 1 )
  {
    memset(s, 0, sizeof(s));
    fgets(s, 999, stdin);
    v4 = strcspn(s, "\n");
    s[v4] = 0;
    if ( !memcmp("corctf{", s, 7uLL) && v4 > 1 && s[v4 - 1] == 125 && s[8] == s[17] && s[9] == s[11] )
    {
      v5 = s[7];
      if ( s[7] == s[16] + 1 && s[14] == s[16] + 4 )
      {
        v6 = &s[8];
        v7 = v3 + 2368;
        v8 = *v20;
        if ( ((*v20)[s[7]] & 8) != 0 )
        {
          while ( 1 )
          {
            v9 = v7;
            v10 = 7;
            do
            {
              v11 = v5 >> v10--;
              *v9 = v11;
              *v9++ &= 1u;
            }
            while ( v10 != -1 );
            v7 += 8;
            if ( &s[18] == v6 )
              break;
            v5 = *v6++;
            if ( (v8[(char)v5] & 8) == 0 )
              goto LABEL_14;
          }
          v3[2456] = 1;
          for ( i = 0LL; i != 64; ++i )
          {
            v13 = 0x5800000000000000LL;
            v3[i + 2816] = ((0x8000000000000000LL >> i) & 0x5800000000000000LL) != 0;
          }                                     // 300000 code asm here
          while ( 1 )
          {
            v14 = 0LL;
            v15 = (int)v6 >> 5;
            do
            {
              v16 = *(char *)(v13 + v14);
              v17 = 0x80000000 >> v14++;
              v11 |= v17 * v16;
            }
            while ( v14 != 32 );
            LODWORD(v6) = (_DWORD)v6 + 32;
            v13 += 32LL;
            *((_DWORD *)v21 + v15) = v11;
            if ( (_DWORD)v6 == 128 )
              break;
            v11 = *((_DWORD *)v21 + ((int)v6 >> 5));
          }
          if ( v21[1] == 0x14353CE419C603BALL )
            break;
        }
      }
    }
LABEL_14:
    puts("Try again: ");
  }
  puts("Nice!\n");
  v24 = 0;
  memset(&v23[2], 0, 48);
  v23[1] = 0x7D202020202020uLL;
  *(__m128i *)v22 = _mm_load_si128((const __m128i *)&xmmword_EE050);
  v23[0] = _mm_load_si128((const __m128i *)&xmmword_EE060);
  *(_QWORD *)((char *)v23 + 2) = v21[0] ^ 0xC6FA039DFDEC7AE5LL;
  for ( j = 0LL; j != 11; ++j )
    *((_BYTE *)v23 + j + 11) = s[j + 7] + 1;
  puts(v22);
  return 0LL;
}
```

Đầu tiên chương trình sẽ kiểm tra format flag, sau đó là một số điều kiện check chuỗi khác như dưới đây

```C
    if ( !memcmp("corctf{", s, 7uLL) && v4 > 1 && s[v4 - 1] == 125 && s[8] == s[17] && s[9] == s[11] )
    {
      v5 = s[7];
      if ( s[7] == s[16] + 1 && s[14] == s[16] + 4 )
      {
```

Tiếp theo ta có đoạn chương trình này:

```C
v8 = *v20;
if ( ((*v20)[s[7]] & 8) != 0 )
        {
          while ( 1 )
          {
            v9 = v7;
            v10 = 7;
            do
            {
              v11 = v5 >> v10--;
              *v9 = v11;
              *v9++ &= 1u;
            }
            while ( v10 != -1 );
            v7 += 8;
            if ( &s[18] == v6 )
              break;
            v5 = *v6++;
            if ( (v8[(char)v5] & 8) == 0 )
              goto LABEL_14;
          }
```

``v20`` là mảng trả về sau khi chương trình gọi hàm ``__ctype_b_loc()``, mục đích của hàm này nhằm trả về một mảng mà ở đó thứ tự của mỗi phần tử ứng với một kí tự ASCII còn giá trị của nó là đặc tính của kí tự ASCII đó (số, chữ, ...). Bằng cách sử dụng hàm trên, có thể thấy mục đích của lệnh ``((*v20)[s[7]] & 8) != 0`` nhằm kiểm tra xem phần tử đang xét có phải là chữ thường, chữ hoa hoặc số hay không? Tương tự với lệnh ``(v8[(char)v5] & 8) == 0``. Sau khi kiểm tra, nếu phần tử thoả mãn yêu cầu thì chuyển nó sang dạng 1 mảng nhị phân 8 bit. Phần tử đầu tiên được check là phần tử thứ 7, tiếp tục vòng lặp cho đến khi gặp phần tử thứ 18 ``&s[18] == v6``. Từ đây suy ra chương trình chỉ biến đổi phần bên trong không bao gồm format flag và phần này có độ dài là 11 kí tự

Sau khi chuyển chuỗi nhập vào sang dạng nhị phân, chương trình thực hiện một số bước khai báo mặc định trước khi vào đoạn 300000 dòng code như dưới đây

```C
for ( i = 0LL; i != 64; ++i )
          {
            v13 = 0x5800000000000000LL;
            v3[i + 2816] = ((0x8000000000000000LL >> i) & 0x5800000000000000LL) != 0;
          } 
```

Thực hiện biến đổi flag xong, thì chương trình lại tiếp tục convert kết quả từ dạng bin sang dạng số nguyên thường và thực hiện so sánh như dưới

```C
while ( 1 )
          {
            v14 = 0LL;
            v15 = (int)v6 >> 5;
            do
            {
              v16 = *(char *)(v13 + v14);
              v17 = 0x80000000 >> v14++;
              v11 |= v17 * v16;
            }
            while ( v14 != 32 );
            LODWORD(v6) = (_DWORD)v6 + 32;
            v13 += 32LL;
            *((_DWORD *)v21 + v15) = v11;
            if ( (_DWORD)v6 == 128 )
              break;
            v11 = *((_DWORD *)v21 + ((int)v6 >> 5));
          }
          if ( v21[1] == 0x14353CE419C603BALL )
            break;
```

Nếu điều kiện thoả mãn thì chương trình sẽ in flag thật, còn nếu không thì chương trình bắt người dùng thử lại.

Đến đây thì phần còn lại cần phải phân tích là đoạn code asm dài 300000 kia :(

### 300000 dòng asm

Đoạn đầu tiên thì chương trình có vẻ như đang khai báo hằng số mặc định nào đó, khi mà dưới đây toàn là đẩy 1 và 0 vào trong một mảng nào đấy

![image](https://github.com/user-attachments/assets/4a2ca0cd-9c3e-4c57-9435-919186f8c4dd)

Sau một vài bước biến đổi, ta tiếp tục thấy một đoạn khai báo khác cũng là đẩy 1 và 0, nhưng khác ở chỗ là đoạn này biến được đẩy vào không theo một quy luật hay quy tắc đặc sắc nào giống như một đoạn code trước đó

![image](https://github.com/user-attachments/assets/70d703c1-d222-4c75-b13a-8a17c9aa5aed)

Có vẻ đây là một mảng hằng số đặc biệt, mình sẽ lấy nó ra sau đó chuyển sang dạng hex xem sao

```python
K_arr = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1]
sus = []
for i in range(0, 0x800, 0x20):
    sus.append(int(''.join(str(b) for b in K_arr[i:i+0x20]), 2))
sus2 = []
for i in range(64):
    sus2.append(int.from_bytes(sus[i].to_bytes(4, byteorder = 'big'), byteorder='little'))
for i in sus2:
    print(hex(i), end=', ')
```

Kết quả là thu được là một mảng 64 phần tử như dưới đây:

```
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
```

Đến đây thì mình nhận ra mảng 64 phần tử này chính là mảng K trong thuật toán Hash [MD5](https://en.wikipedia.org/wiki/MD5#Pseudocode)

Phần sau của chương trình là một đoạn biến đổi gì đó rất dài và loằng ngoằng, có vẻ là phần xử lý chính. Tuy nhiên dựa vào mảng 64 phần tử mình lấy được trên kia. Rất có thể 300000 dòng code này chính là thuật toán MD5 hoặc là MD5 nhưng bị custom.

Thuật toán MD5 còn 4 hằng số A, B, C, D khác có giá trị lần lượt là ``0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476``, tuy nhiên không thấy chương trình khai báo thêm hằng số ở đâu nữa, xem lại chương trình thì thấy ở phần đầu có khai báo một mảng 128 số 0, rất có thể đây chính là các giá trị A, B, C, D đã bị sửa lại. Dựa vào đó mình sẽ thử code lại chương trình bằng python dựa theo hướng MD5 nhưng bị custom bằng cách sửa 4 hằng số A, B, C, D

```python
import math

# This list maintains the amount by which to rotate the buffers during processing stage
rotate_by = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
			 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# This list maintains the additive constant to be added in each processing step.
constants = [int(abs(math.sin(i+1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]
# STEP 1: append padding bits s.t. the length is congruent to 448 modulo 512
# which is equivalent to saying 56 modulo 64.
# padding before adding the length of the original message is conventionally done as:
# pad a one followed by zeros to become congruent to 448 modulo 512(or 56 modulo 64).
def pad(msg):
	msg_len_in_bits = (8*len(msg)) & 0xffffffffffffffff
	msg.append(0x80)

	while len(msg)%64 != 56:
		msg.append(0)

# STEP 2: append a 64-bit version of the length of the length of the original message
# in the unlikely event that the length of the message is greater than 2^64,
# only the lower order 64 bits of the length are used.

# sys.byteorder -> 'little'
	msg += msg_len_in_bits.to_bytes(8, byteorder='little') # little endian convention
	# to_bytes(8...) will return the lower order 64 bits(8 bytes) of the length.
	
	return msg


# STEP 3: initialise message digest buffer.
# MD buffer is 4 words A, B, C and D each of 32-bits.

# init_MDBuffer = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
init_MDBuffer = [0x00, 0x00, 0x00, 0x00]

# UTILITY/HELPER FUNCTION:
def leftRotate(x, amount):
	x &= 0xFFFFFFFF
	return (x << amount | x >> (32-amount)) & 0xFFFFFFFF


# STEP 4: process the message in 16-word blocks
# Message block stored in buffers is processed in the follg general manner:
# A = B + rotate left by some amount<-(A + func(B, C, D) + additive constant + 1 of the 16 32-bit(4 byte) blocks converted to int form)

def processMessage(msg):
	init_temp = init_MDBuffer[:] # create copy of the buffer init constants to preserve them for when message has multiple 512-bit blocks

	# message length is a multiple of 512bits, but the processing is to be done separately for every 512-bit block.
	for offset in range(0, len(msg), 64):
		A, B, C, D = init_temp # have to initialise MD Buffer for every block
		block = msg[offset : offset+64] # create block to be processed
		# msg is processed as chunks of 16-words, hence, 16 such 32-bit chunks
		for i in range(64): # 1 pass through the loop processes some 32 bits out of the 512-bit block.
			if i < 16:
				# Round 1
				func = lambda b, c, d: (b & c) | (~b & d)
				# if b is true then ans is c, else d.
				index_func = lambda i: i

			elif i >= 16 and i < 32:
				# Round 2
				func = lambda b, c, d: (d & b) | (~d & c)
				# if d is true then ans is b, else c.
				index_func = lambda i: (5*i + 1)%16

			elif i >= 32 and i < 48:
				# Round 3
				func = lambda b, c, d: b ^ c ^ d
				# Parity of b, c, d
				index_func = lambda i: (3*i + 5)%16
			
			elif i >= 48 and i < 64:
				# Round 4
				func = lambda b, c, d: c ^ (b | ~d)
				index_func = lambda i: (7*i)%16

			F = func(B, C, D) # operate on MD Buffers B, C, D
			G = index_func(i) # select one of the 32-bit words from the 512-bit block of the original message to operate on.

			to_rotate = A + F + constants[i] + int.from_bytes(block[4*G : 4*G + 4], byteorder='little')
			newB = (B + leftRotate(to_rotate, rotate_by[i])) & 0xFFFFFFFF
				
			A, B, C, D = D, newB, B, C
			# rotate the contents of the 4 MD buffers by one every pass through the loop

		# Add the final output of the above stage to initial buffer states
		for i, val in enumerate([A, B, C, D]):
			init_temp[i] += val
			init_temp[i] &= 0xFFFFFFFF
		# The init_temp list now holds the MD(in the form of the 4 buffers A, B, C, D) of the 512-bit block of the message fed.

	
	# The same process is to be performed for every 512-bit block to get the final MD(message digest).

	
	# Construct the final message from the final states of the MD Buffers
	return sum(buffer_content<<(32*i) for i, buffer_content in enumerate(init_temp))


def MD_to_hex(digest):
	# takes MD from the processing stage, change its endian-ness and return it as 128-bit hex hash
	raw = digest.to_bytes(16, byteorder='little')
	return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


def md5(msg):
	msg = bytearray(msg, 'ascii') # create a copy of the original message in form of a sequence of integers [0, 256)
	msg = pad(msg)
	processed_msg = processMessage(msg)
	# processed_msg contains the integer value of the hash
	message_hash = MD_to_hex(processed_msg)
	return message_hash

print(md5('h01b1cdkfg0'))
```

Để kiểm tra giả thuyết của mình, thì mình sẽ thử với input là ``corctf{h01b1cdkfg0xxxxx}``, khi đó phần input sẽ bị xử lý là đoạn ``h01b1cdkfg0``, dưới đây là kết quả thu được sau khi debug

![image](https://github.com/user-attachments/assets/8fa26332-f3f8-4240-bfc4-967de878ad52)

Còn đây là kết quả sau khi chạy script của mình dựng lại: ``166dea52730f5d17e0bb3e51cf92e35c``. Đến đây thì có vẻ hướng đi của mình đã đúng.

Tổng kết lại chương trình sẽ thực hiện như sau: 
- Yêu cầu người dùng nhập chuỗi dài hơn 11 kí tự nằm trong format Flag, chuối đó phải thoả các điều kiện dưới đây:
  ```
  s[1] == s[10]
  s[2] == s[4]
  s[0] == chr(ord(s[9])+1)
  s[7] == chr(ord(s[9])+4)
  ```
- Tiếp theo là biến đổi chuỗi 11 kí tự trên bằng thuật toán băm MD5 đã bị custom bằng cách sửa A, B, C, D thành 4 số 0
- Cuối cùng là check Hash thu được xem 8 byte cuối của nó có trùng với ``19c603ba14353ce4`` hay không. Nếu đúng thì biến đổi và gen ra Flag thật của chương trình

### Solution

Như ta biết thì MD5 là một thuật toán Hash, nó không thể dịch ngược, vì vậy để tìm được chuỗi gốc thì chỉ còn nước là phải thực hiện Brute-Force :(

Nhưng chuỗi đầu vào tận 11 kí tự, thêm một vài điều kiện nữa thì nó còn 7 kí tự cần phải tìm. Việc brute-force 7 kí tự vẫn là quá khó :(

Sau khi giải kết thúc, mình đọc solution trên discord và thấy rằng nên sửa lại tool [hashcat](https://github.com/hashcat/hashcat) và dùng nó để brute-force hiệu quả hơn

![image](https://github.com/user-attachments/assets/7c8920db-68ea-43b0-ba8d-0c47d2c732be)

