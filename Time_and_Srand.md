# Cách xử lý một số bài liên quan đến Time và Srand

- ``time``: đây là một hàm trong Linux cho phép lấy số giây kể từ thời điểm ``1/1/1970, 00:00:00 UTC`` đến thời điểm mà người dùng chỉ định. Néu ``time(0)`` thì thời điểm chỉ định là thời điểm hiện tại

- ``srand`` và ``rand``: hàm ``srand`` với một giá trị do người dùng truyền vào (gọi là seed) sẽ "khoá cố định" các giá trị của hàm ``rand`` theo quy luật nhất định nào đó

Các dạng bài liên quan đến Time và Srand thường sẽ có cấu trúc như sau:

```C
v3 = time(0LL);
srand(v3);

// gọi hàm rand và làm gì đó bla bla
```

Thường các bài liên quan đến Time và Srand sẽ có file thực thi là ELF, mục đích để gây nhầm lẫn cho người chơi trong việc phân tích bởi vì Srand của Windows và Linux là khác nhau, và chúng cũng khác nhau với mỗi ngôn ngữ lập trình khác nhau.

Có thể viết lại cách triển khai trên bằng Python để dễ viết Script giải, bằng cách lấy địa chỉ các hàm trên trong thư việc ``libc.so.6`` của Linux

```python
import datetime
import ctypes

# dựng lại hàm time dựa trên cách hoạt động của nó
specific_time = datetime.datetime.now(datetime.timezone.utc)
epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
seconds_since_epoch = int((specific_time - epoch).total_seconds())

# sử dụng thư viện libc.so.6 để lấy hàm
libc = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
print(seconds_since_epoch == libc.time(0))
seed = 0x88
libc.srand(seed)
for i in range(0x88):
    print(libc.rand(), end= ' ')
print()
```

Dưới đây là ví dụ một vài bài liên quan đến ``time`` và ``srand`` trong các giải CTF thực tế

## Casino - HackTheBox Buusiness CTF 2024

Challenge cho một file ELF, mở bằng IDA thì hàm Main trông như dưới đây

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+Bh] [rbp-5h] BYREF
  unsigned int i; // [rsp+Ch] [rbp-4h]

  puts("[ ** WELCOME TO ROBO CASINO **]");
  puts(
    "     ,     ,\n"
    "    (\\____/)\n"
    "     (_oo_)\n"
    "       (O)\n"
    "     __||__    \\)\n"
    "  []/______\\[] /\n"
    "  / \\______/ \\/\n"
    " /    /__\\\n"
    "(\\   /____\\\n"
    "---------------------");
  puts("[*** PLEASE PLACE YOUR BETS ***]");
  for ( i = 0; i <= 0x1C; ++i )
  {
    printf("> ");
    if ( (unsigned int)__isoc99_scanf(" %c", &v4) != 1 )
      exit(-1);
    srand(v4);
    if ( rand() != check[i] )
    {
      puts("[ * INCORRECT * ]");
      puts("[ *** ACTIVATING SECURITY SYSTEM - PLEASE VACATE *** ]");
      exit(-2);
    }
    puts("[ * CORRECT *]");
  }
  puts("[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]");
  return 0;
}
```

Về cơ bản, chương trình đang lấy srand nhiều lần với seed là từng kí tự của flag, sau đó gọi ``rand`` và check chúng với data ``check`` có sẵn

```
.data:0000000000004080 public check
.data:0000000000004080 ; _DWORD check[29]
.data:0000000000004080 check dd 244B28BEh, 0AF77805h, 110DFC17h, 7AFC3A1h, 6AFEC533h, 4ED659A2h, 33C5D4B0h, 286582B8h, 43383720h
.data:0000000000004080                                         ; DATA XREF: main+91↑o
.data:0000000000004080 dd 55A14FCh, 19195F9Fh, 43383720h, 63149380h, 615AB299h, 6AFEC533h, 6C6FCFB8h, 43383720h, 0F3DA237h
.data:0000000000004080 dd 6AFEC533h, 615AB299h, 286582B8h, 55A14FCh, 3AE44994h, 6D7DFE9h, 4ED659A2h, 0CCD4ACDh, 57D8ED64h, 615AB299h
.data:0000000000004080 dd 22E9BC2Ah
.data:0000000000004080 _data ends
.data:0000000000004080
```

Vậy cần phải viết một Script để Brute-Force từng kí tự của Flag, lấy chúng làm seed rồi gọi hàm rand để kiểm tra với data có sẵn

```python
import ctypes

libc = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
checker =[0x244B28BE, 0x0AF77805, 0x110DFC17, 0x7AFC3A1, 0x6AFEC533, 0x4ED659A2, 0x33C5D4B0, 0x286582B8, 0x43383720,
0x55A14FC, 0x19195F9F, 0x43383720, 0x63149380, 0x615AB299, 0x6AFEC533, 0x6C6FCFB8, 0x43383720, 0x0F3DA237,
0x6AFEC533, 0x615AB299, 0x286582B8, 0x55A14FC, 0x3AE44994, 0x6D7DFE9, 0x4ED659A2, 0x0CCD4ACD, 0x57D8ED64, 0x615AB299,
0x22E9BC2A]

flag = []
for i in range(len(checker)):
    for j in range(0x20, 0xFF):
        libc.srand(j)
        if libc.rand() == checker[i]:
            flag.append(j)
            break

for i in flag:
    print(chr(i), end='')
print()
```

Chạy Script trên bằng máy ảo Linux, thu được flag của Challenge: ``HTB{r4nd_1s_v3ry_pr3d1ct4bl3}``

## Paranonia - AKASEC CTF 2024

Challenge cho một file ELF, mở bằng IDA thì hàm Main trông như dưới đây

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v4; // ebx
  int v5; // eax
  unsigned __int64 i; // [rsp+8h] [rbp-18h]

  v3 = time(0LL);
  srand(v3);
  for ( i = 0LL; i <= 17; ++i )
  {
    v4 = flag[i];
    v5 = rand();
    printf("%i ", v4 ^ ((unsigned __int8)(((unsigned int)(v5 >> 31) >> 24) + v5) - ((unsigned int)(v5 >> 31) >> 24)));
  }
  putchar(10);
  return 0;
}
```

Về cơ bản thì chương trình gọi ``time(0)`` để lấy thời gian hiện tại, sau đó dùng giá trị lấy được làm seed cho hàm ``srand``, cuối cùng là mã hoá Flag bằng cách Xor ``rand`` với từng kí tự của nó, sau đó in kết quả Xor được ra màn hình.

Flag trong File thực thi chắc chắn là Flag Fake, còn Flag thật là flag được dùng để mã hoá trên Server của giải. Không thể nào DDOS server của giải để lấy Flag được :))). Vậy nên cần viết một Script để Brute Force seed của Srand.

Giải AKASEC CTF bắt đầu vào lúc ``Fri, 07 June 2024, 13:37 UTC``, khi chạy server của giải, server trả về cho chúng ta mảng giá trị của Flag sau khi bị encrypt như dưới đây:

```C
outp = [157, 97, 139, 62, 224, 28, 232, 120, 137, 76, 238, 96, 108, 78, 189, 66, 136, 193, 119, 198, 69, 130, 234, 107, 39, 68, 206, 81, 114, 250, 180, 118, 160, 179, 19, 101]
```

Chúng ta sẽ dựa vào thông tin trên và cách hoạt động của challenge để viết script lấy flag:

```python
import ctypes
import datetime

# lấy giá trị của hàm time(0) tại thời điểm Fri, 07 June 2024, 13:37 UTC
specific_time = datetime.datetime(2024, 6, 7, 13, 37, 0, tzinfo=datetime.timezone.utc)
epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
seconds_since_epoch = int((specific_time - epoch).total_seconds())

# brute-force seed
outp = [157, 97, 139, 62, 224, 28, 232, 120, 137, 76, 238, 96, 108, 78, 189, 66, 136, 193, 119, 198, 69, 130, 234, 107, 39, 68, 206, 81, 114, 250, 180, 118, 160, 179, 19, 101]
libc = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
for i in range(seconds_since_epoch, seconds_since_epoch + 0xFFFF, 1):
    libc.srand(i)
    flag = ''
    for j in range(len(outp)):
        rnd = libc.rand() & 0xFF
        flag += chr(outp[j] ^ rnd)
    if 'akasec{' in flag:
        print(f'Seed: {i}')
        print(f'v5: {rnd}')
        print(f'Flag: {flag}')
        break
```

Kết quả sau khi chạy trên Linux:

```
Seed: 1717768390
v5: 24
Flag: akasec{n0t_t00_m4ny_br41nc3lls_l3ft}
```

Vậy ``akasec{n0t_t00_m4ny_br41nc3lls_l3ft}`` là Flag của challenge

## Ví dụ trong trường hợp nếu chương trình không có hàm Srand

Chương trình dưới đây yêu cầu người dùng nhập Username và Password. Nếu đúng thì sẽ chạy lệnh ``cat flag`` để lấy flag. Dễ thấy username là ``admin``

```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  susrandd();
  memset(s, 0, 0x32uLL);
  __isoc99_scanf("%49s", s);
  if ( !strcmp(s, s1) )
  {
    __isoc99_scanf("%49s", s);
    if ( !strcmp(s, SUS_KEY) )
    {
      printf("Welcome, %s!\n", s1);
      if ( !strcmp(s1, "admin") )
        system("cat flag");
    }
    else
    {
      printf("Invalid password!\n");
    }
  }
  else
  {
    printf("Invalid ID!\n");
  }
  return 0LL;
}
```

Vấn đề là ở Password, chương trình gọi hàm ``susrand`` để Gen Password, cấu trúc như dưới đây:

```C
__int64 sub_11B0()
{
  int v1; // [rsp+0h] [rbp-10h]
  int i; // [rsp+4h] [rbp-Ch]

  for ( i = 0; i < 16; ++i )
  {
    v1 = rand() % 3;
    if ( v1 )
    {
      if ( v1 == 1 )
      {
        SUS_KEY[i] = rand() % 26 + 65;
      }
      else if ( v1 == 2 )
      {
        SUS_KEY[i] = rand() % 26 + 97;
      }
    }
    else
    {
      SUS_KEY[i] = rand() % 10 + '0';
    }
  }
  return 0LL;
}
```

Nếu chương trình không có hàm srand thì mặc định seed của srand là 1. Khi đó ta có thể viết code để dựng lại Password như dưới đây

```C
import ctypes

libc = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
sus_key = ''
for i in range(16):
    v1 = libc.rand() % 3
    if v1:
        if v1 == 1:
            sus_key += chr(libc.rand() % 26 + 65)
        elif v1 == 2:
            sus_key += chr(libc.rand() % 26 + 97)
    else:
        sus_key += chr(libc.rand() % 10 + 0x30)
print(sus_key)
```

Thu được Password là ``W5bQ1dro6Yi9sdRm``, chạy lại chương trình và lấy Flag

```
admin
W5bQ1dro6Yi9sdRm
Welcome, admin!
KCSC{345y_r4nd0m!!!}
```
