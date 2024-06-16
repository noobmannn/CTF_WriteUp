# funchecker

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/ac75273d-1fd6-4133-866e-55d956ef8d54)

Challenge cho chúng ta một file PE64 như dưới đây

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/8504ab04-bdd6-4534-9a6f-cfa5e1303a10)

Mở bằng IDA và xem hàm main của chương trình. Về cơ bản ba hàm ``init0``, ``init1`` và ``init2`` chỉ là khởi tạo giá trị

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/333ff52e-ffee-4e95-92cd-7055076016a2)

Xem nội dung hàm ``maybeHandle``, hàm này cũng gọi hàng loạt hàm khác nhau và hàng loạt các bước xử lý phức tạp nhưng dường như cũng chỉ để khởi tạo môi trường

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/3146eae3-d327-4967-a9bc-5b38b16b73ab)

Vào hàm ``maybeEncryptFlag``, hàm này cũng làm hàng loạt thao tác phức tạp nào đó nhưng cũng chỉ để khởi tạo chương trình

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/bf79ae54-3cc2-4591-b71c-b694d8e32082)

Tuy nhiên phần dưới của hàm này mới là thứ mình cần chú ý

```cpp
if ( maybeHash((_QWORD *)v10, v9, 0i64) == 0xA8A85CFA9660DB0Fui64 && *(_DWORD *)(v7 + 8) == 40 )
  {
    cnt = 0;
    while ( 1 )
    {
      v11 = cnt;
      v12 = *(unsigned __int8 *)(v7 + cnt + 16);
      v15 = 4;
      LODWORD(v13) = 6;
      for ( i = 0; i < 5; ++i )
      {
        v12 ^= __ROR8__(v12, v13) ^ __ROL8__(v12, v15);
        v15 *= 2;
        v13 = (unsigned int)(2 * v13);
      }
      if ( *(_QWORD *)(*(_QWORD *)(qword_7FF74D61C168 + 8) + 8i64 * cnt + 16) != v12 )
        break;
      if ( (int)++cnt >= 40 )
        return print_Invalid_flag_specified_0(&unk_7FF74D5BFA00, v11, v12, v13);
    }
  }
```

Đọc qua nội dung hàm ``maybeHash``, hàm này dường như đang custom lại 1 hàm hash nào đó

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/071cfaa7-3dc1-4817-8d53-bba8ce217f97)

Quay lại hàm ``maybeEncryptFlag``, sau khi đọc kĩ và debug, mình nhận ra rằng sau khi Hash string người dùng nhập vào và kiểm tra với ``0xA8A85CFA9660DB0F``, chương trình tiếp tục check xem độ dài chuỗi được đưa vào có bằng 40 hay không. Từ đây dễ nhận ra độ dài của flag là 40

Sau khi check hash và check độ dài, hàm thực hiện các biến đổi như ở trong if sau đó check với ``qword_7FF74D61C168``, bằng cách debug, mình dễ dàng lấy được các giá trị sau khi encrypt

```python
enc = [0x0FA97D8710C8B9B54, 0x0EB82CC74589FDA54, 0x0EE928C654D8BDF01, 0x5A35D0732E291BFE, 0x0FF879860199F9E01, 0x690AEC7CD215D8FE, 0x7D0FB86893159CAB, 0x0F30C0333F3C0FFF, 0x0BEC388645CDA9F54, 0x0F30C0333F3C0FFF, 0x5F2590623B3D1EAB, 0x0C9A8E47EF0B75854, 0x226E7C5ABD78D301, 0x0DDADB06AB1B71C01, 0x5F61C4322E6D4FAA, 0x6C1AAC6DC701DDAB, 0x0F7494632A6C5EFE, 0x0EB82CC74589FDA54, 0x226E7C5ABD78D301, 0x0BBD3C87549CE9A01, 0x0FFC3CC300CCFCF00, 0x0FA97D8710C8B9B54, 0x0FFC3CC300CCFCF00, 0x0BBD3C87549CE9A01, 0x0EB82CC74589FDA54, 0x5F61C4322E6D4FAA, 0x7D0FB86893159CAB, 0x0AFD69C6108CEDE54, 0x226E7C5ABD78D301, 0x7D0FB86893159CAB, 0x4E3084676F295FAB, 0x5A35D0732E291BFE, 0x5F61C4322E6D4FAA, 0x0FA97D8710C8B9B54, 0x0F7494632A6C5EFE, 0x226E7C5ABD78D301, 0x4E3084676F295FAB, 0x0F30C0333F3C0FFF, 0x5A35D0732E291BFE, 0x88ECF47AB5F25901]
```

Dựa vào những thông tin đã phân tích ở trên, mình viết được script để lấy flag của bài

```python
from z3 import *

enc = [0x0FA97D8710C8B9B54, 0x0EB82CC74589FDA54, 0x0EE928C654D8BDF01, 0x5A35D0732E291BFE, 0x0FF879860199F9E01, 0x690AEC7CD215D8FE, 0x7D0FB86893159CAB, 0x0F30C0333F3C0FFF, 0x0BEC388645CDA9F54, 0x0F30C0333F3C0FFF, 0x5F2590623B3D1EAB, 0x0C9A8E47EF0B75854, 0x226E7C5ABD78D301, 0x0DDADB06AB1B71C01, 0x5F61C4322E6D4FAA, 0x6C1AAC6DC701DDAB, 0x0F7494632A6C5EFE, 0x0EB82CC74589FDA54, 0x226E7C5ABD78D301, 0x0BBD3C87549CE9A01, 0x0FFC3CC300CCFCF00, 0x0FA97D8710C8B9B54, 0x0FFC3CC300CCFCF00, 0x0BBD3C87549CE9A01, 0x0EB82CC74589FDA54, 0x5F61C4322E6D4FAA, 0x7D0FB86893159CAB, 0x0AFD69C6108CEDE54, 0x226E7C5ABD78D301, 0x7D0FB86893159CAB, 0x4E3084676F295FAB, 0x5A35D0732E291BFE, 0x5F61C4322E6D4FAA, 0x0FA97D8710C8B9B54, 0x0F7494632A6C5EFE, 0x226E7C5ABD78D301, 0x4E3084676F295FAB, 0x0F30C0333F3C0FFF, 0x5A35D0732E291BFE, 0x88ECF47AB5F25901]
res = []
flag = [BitVec('x1[%d]'%i, 64) for i in range(40)]
s = Solver()
for i in range(len(flag)):
    s.add(flag[i] > 0x20)
    s.add(flag[i] < 0x7f)
cnt = 0
while 1:
    v12 = flag[cnt]
    v15 = 4
    v13 = 6
    for i in range(5):
        v12 ^= (RotateRight(v12, v13) ^ RotateLeft(v12, v15))
        v15 *= 2
        v13 *= 2
    res.append(v12)
    cnt += 1
    if cnt >= 40:
        break
for i in range(40):
    s.add(res[i] == enc[i])
if s.check() == sat:
    m = s.model()
    resstr = ''
    solution = [m[flag[i]].as_long() for i in range(40)]
    resstr += ''.join([chr(c) for c in solution])
    print(resstr)
else:
    print('Fail')
```

Kết quả script trên là ``vsctf{n0b0dy_l1kes_r3v3rs1ng_nat1ve_a0t}``, đây chính là flag của challenge

# Flag

``vsctf{n0b0dy_l1kes_r3v3rs1ng_nat1ve_a0t}``
