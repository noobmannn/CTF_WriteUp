# ROP

![](https://github.com/noobmannn/CTF_WriteUp/blob/17e24ea0f78b1dc77fca6a6a7e977456b692b268/TAMUctf-2024/ROP/Img/1.png)

Mở bằng die, đây là file ELF64

![](https://github.com/noobmannn/CTF_WriteUp/blob/17e24ea0f78b1dc77fca6a6a7e977456b692b268/TAMUctf-2024/ROP/Img/2.png)

Chạy thử thì file yêu cầu nhập Flag có dạng như này

![](https://github.com/noobmannn/CTF_WriteUp/blob/17e24ea0f78b1dc77fca6a6a7e977456b692b268/TAMUctf-2024/ROP/Img/3.png)

Mở bằng IDA, chương trình có một hàm main và một hàm vuln như này

![](https://github.com/noobmannn/CTF_WriteUp/blob/d544559425c674ec85b63c3392b47814d56b72b7/TAMUctf-2024/ROP/Img/4.png)

Đọc kĩ có thể thấy bài này sử dụng kĩ thuật [ROPchain](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming), từ đó bằng cách sử dụng GDB, ta có thể dựng lại cơ bản luồng hoạt động của chương trình ở [đây](https://github.com/noobmannn/CTF_WriteUp/blob/d544559425c674ec85b63c3392b47814d56b72b7/TAMUctf-2024/ROP/Resc/message.txt)

Đọc qua luồng thì thấy chương trình đầu tiên check độ dài input mình nhập vào ở đây

```
POP_RSI
0x00000000005000f6   string
0x0000000000500005   mov    QWORD PTR [rsi], rdi


strlen
0x0000000000500031   call rax
0x0000000000500009


//rdi is now length
POP_RSI
0x0000000025649d94
0x000000000050000d push   rdi
                0x50000e:	push   rsi
                0x50000f:	call   0x40b520 <rand> // rax 0x25649d88
                0x500014:	pop    rsi
                0x500015:	pop    rdi
                0x500016:	xor    rdi,rax
                0x500019:	xor    rdi,rsi
                0x50001c:	mov    rdi,0x0
                0x500023:	mov    r9,0x1  
                0x50002a:	cmove  rdi,r9
                0x50002e:	xor    esi,esi
                0x500030:	ret    
```

Bằng cách đọc kĩ và dịch ngược lại, có thể dễ dàng nhận ra độ dài của input nhập vào là 28 kí tự

Sau khi check input, chương trình chia 28 kí tự của flag làm 4 phần, mỗi phần 7 kí tự, và cứ mỗi một phần lại cho qua một hàm encrypt như dưới đây

![](https://github.com/noobmannn/CTF_WriteUp/blob/165e47758b8dae703004b1459519a1176bab9d8b/TAMUctf-2024/ROP/Img/5.png)

Kêt quả của hàm trên được lưu vào rdi, sau đó kết quả này được xor với giá trị của hàm random, hàm random này đã được seed nên nó sẽ chỉ luôn cho ra giá trị cố đinh. Sau đó sẽ kiểm tra tiếp xem nếu rdi và rsi bằng nhau thì chương trình sẽ check tiếp các đoạn input còn lại và cũng dùng hàm này để encrypt input và check. Nếu pass qua toàn bộ các đoạn check thì chương trình in ra chuỗi ``That is Flag`` và kết thúc

![](https://github.com/noobmannn/CTF_WriteUp/blob/165e47758b8dae703004b1459519a1176bab9d8b/TAMUctf-2024/ROP/Img/6.png)

Phân tích thuật toán được dùng để encrypt, có thể thấy đây là thuật toán [nhân bình phương có lặp](https://en.wikipedia.org/wiki/Exponentiation_by_squaring) để tính luỹ thừa theo mod, hiểu đơn giản thì chương trình đang muốn tính giá trị ```pow(37, x, 0x1FFFFFFFFFFFFFFF)``` với x là số được ghép từ mỗi đoạn 7 kí tự của flag

Dựa vào đó ta viết được Script để lấy flag:

```python
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
```

Chạy Script trên https://sagecell.sagemath.org/ , ta lấy được flag của bài

![](https://github.com/noobmannn/CTF_WriteUp/blob/362c5558132d106d6d06675b0ff604cde315ca2b/TAMUctf-2024/ROP/Img/7.png)

# Flag

``gigem{i_<3_m3rs3nn3_pr1m35!}``
