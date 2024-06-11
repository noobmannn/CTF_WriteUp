# Packeta

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/b5186b88-9472-42fc-a2c1-efec9b9b8186)

Chal cho ta 1 file binary ``flag`` và 1 file ELF-64 ``packeta``

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/e98062ee-7738-4112-996d-54603762bdf4)

Xem qua hàm main của chương trình bằng IDA, về cơ bản chương trình yêu cầu người dùng truyền vào một file ELF, sau đó đọc file, check Signature của file, rồi gọi hai hàm ``sub_55F026444842`` và ``sub_55F026444905`` để tiến hành các bước khởi tạo cơ bản cho chương trình

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/e5374053-3e42-4bbd-ab02-7f5096517d44)

Tiếp theo chương trình chạy đến hàm ``gen_rand_arr``, hàm này tiến hành gen ra một Key dài 15 kí tự từ tập hợp ``0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ``, dựa trên việc Random các vị trí của tập hợp trên theo một ``srand`` cố định được tính như ở hình dưới đây

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/625d2761-e8b4-4f26-8b43-6ff7d6c962d6)

Sau đó chương trình mã hoá file người dùng truyền vào bằng hàm dưới đây

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/806c0402-ab4b-4ada-b802-ac806db38e86)

Đọc hàm ``checkSection``, có thể nhận ra chương trình chỉ mã hoá 3 section ``.text``, ``.data`` và ``.rodata`` của file ELF được truyền vào

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/7d847d2f-e7d5-4c5a-bd3e-8118aeb5839f)

Tiếp theo chương trình gọi hàm ``rc4_enc`` để mã hoá các section được chọn

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/41419490-21d2-4278-b997-94a19016186d)

Đọc nội dung hai hàm ``ksa`` và ``prga``, dễ nhận thấy đây là thuật toán mã hoá RC4

![rc4](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/6ddf8d6d-1a97-4ddd-aba3-fbe04ecb52e4)

Tổng kết lại, chương trình yêu cầu người dùng truyền vào một file ELF, và mã hoá ba section ``.text``, ``.data`` và ``.rodata`` của file đó bằng thuật toán mã hoá RC4, với Key được gen từ tập hợp ``0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`` dựa vào việc Random các vị trí của tập hợp trên theo một ``srand`` cố định được tính từ thời gian thực bằng hàm ``time``

Chal còn cho chúng ta một file binary ``flag``, có định dạng là ELF-64, vậy có thể hiểu file này có các section ``.text``, ``.data`` và ``.rodata`` đã bị mã hoá bằng file ``packeta``, và ta cần phải dịch ngược nó

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/bfc22e70-3e67-4cc5-9d60-a756720be52b)

Trong file ELF, section ``.text`` là section chứa mã thực thi, tức là các lệnh máy được thực hiện khi chương trình được chạy, section ``.data`` chứa dữ liệu khởi tạo với giá trị không được thay đổi trong quá trình thực thi và dữ liệu trong ``.data`` thường là các biến toàn cục hoặc tĩnh được khởi tạo với giá trị cụ thể, còn section ``rodata`` chứa dữ liệu chỉ để đọc, bao gồm các hằng số và chuỗi mà không được phép sửa đổi trong quá trình thực thi. 

Section ``.text`` chứa mã thực thi của chương trình, tức là nó sẽ gồm nhiều hàm khác nhau, vậy để nhận diện được section này, ta cần phải dựa vào các opcode đầu tiên của hàm ``_start``, hàm đầu tiên trong section ``.text``, tương ứng với các lệnh assembly thường sẽ bị mặc định bởi cấu trúc của chương trình.

Thường có hai loại opcode phổ biến để khởi đầu hàm ``_start`` trong ELF-64:
- ``b'\x31\xed\x49\x89\xd1``, tương ứng với các lệnh assembly:
  ```asm
  xor ebp, ebp
  mov r9, rdx
  ```
- ``b'\xf3\x0f\x1e\xfa\x31\xed'``, tương ứng với các lệnh assembly:
  ```asm
  endbr64
  xor ebp, ebp
  ```

Vậy thì mình sẽ viết một script để brute-force seed của hàm srand trong thư viên ``libc.so.6``, dựa theo các dấu hiệu của ``.text`` mà mình đã phân tích ở trên

```python
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
    if op == b'\xf3\x0f\x1e\xfa\x31' or op == b'\x31\xed\x49\x89\xd1':
        print('Key RC4: ', key)
        print('Opcode Header: ', op)
        print('Seed: ', hex(seed))
        print('Cipher .text: ', cipher)
        rightSeed = seed
        break
```

Chạy script trên bằng python của Linux, thu được kết quả như dưới đây

```
Key RC4:  K6dhNNBjcWv8mLW9
Opcode Header:  b'1\xedI\x89\xd1'
Seed:  0x13b6
Cipher .text:  b'1\xedI\x89\xd1^H\x89\xe2H\x83\xe4\xf0PTE1\xc01\xc9H\x8d=\xce\x00\x00\x00\xff\x15?/\x00\x00\xf4f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f@\x00H\x8d=\x010\x00\x00H\x8d\x05\xfa/\x00\x00H9\xf8t\x15H\x8b\x05\x1e/\x00\x00H\x85\xc0t\t\xff\xe0\x0f\x1f\x80\x00\x00\x00\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00H\x8d=\xd1/\x00\x00H\x8d5\xca/\x00\x00H)\xfeH\x89\xf0H\xc1\xee?H\xc1\xf8\x03H\x01\xc6H\xd1\xfet\x14H\x8b\x05\xed.\x00\x00H\x85\xc0t\x08\xff\xe0f\x0f\x1fD\x00\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfa\x80=\x89/\x00\x00\x00u+UH\x83=\xca.\x00\x00\x00H\x89\xe5t\x0cH\x8b=\x06/\x00\x00\xe8)\xff\xff\xff\xe8d\xff\xff\xff\xc6\x05a/\x00\x00\x01]\xc3\x0f\x1f\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfa\xe9w\xff\xff\xffUH\x89\xe5H\x83\xec@\xc7E\xc0$\x00\x00\x00\xc7E\xc4\x1d\x00\x00\x00\xc7E\xc8u\x00\x00\x00\xc7E\xcc*\x00\x00\x00\xc7E\xd0q\x00\x00\x00\xc7E\xd4\x1d\x00\x00\x00\xc7E\xd8$\x00\x00\x00\xc7E\xdc.\x00\x00\x00\xc7E\xe0v\x00\x00\x00\xc7E\xe4t\x00\x00\x00\xc7E\xe8B\x00\x00\x00H\x8d\x05\x9b.\x00\x00H\x89\xc6H\x8d\x05U\x0e\x00\x00H\x89\xc7\xb8\x00\x00\x00\x00\xe8\x84\xfe\xff\xff\xc7E\xfc\x00\x00\x00\x00\xeb%\x8bE\xfcH\x98H\x8d\x14\x85\x00\x00\x00\x00H\x8d\x05\x87.\x00\x00\x8b\x04\x02\x83\xf0B\x89\xc7\xe8J\xfe\xff\xff\x83E\xfc\x01\x83}\xfc\x0c~\xd5\xc7E\xf8\x00\x00\x00\x00\xeb\x17\x8bE\xf8H\x98\x8bD\x85\xc0\x83\xf0B\x89\xc7\xe8$\xfe\xff\xff\x83E\xf8\x01\x83}\xf8\n~\xe3\xbf}\x00\x00\x00\xe8\x10\xfe\xff\xff\xb8\x00\x00\x00\x00\xc9\xc3'
```

Thu được seed đúng để mã hoá file là ``0x13B6``, từ đây ta patch lại seed của chương trình bằng giá trị trên sau đó chạy lại, thu được 1 file ``new`` mới, chạy file này ta lấy được flag của challenge

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ./new 
AKASEC{h4lf_p4ck_h4lf_7h3_fl46}   
```

# Flag

```AKASEC{h4lf_p4ck_h4lf_7h3_fl46}```
