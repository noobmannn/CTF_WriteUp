# SatelliteHijack

Challange cho chúng ta một file ELF64 ``satellite`` và một file thư viện của linux ``library.so`` 

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/53a6a475-0d45-4f35-bccb-45b88faadf12)

Khi run file, chương trình sẽ hiện lên cái Thumbnail như dưới và cứ liên tục bắt người dùng nhập gì đó

```
         ,-.
        / \  `.  __..-,O ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈
       :   \ --''_..-'.'
       |    . .-' `. '.
       :     .     .`.'
        \     `.  /  ..
        \      `.   ' .
          `,       `.   \
         ,|,`.        `-.\
        '.||  ``-...__..-`
         |  |
         |__|
         /||\
        //||\\
       // || \\
    __//__||__\\__
   '--------------' 
| READY TO TRANSMIT |
> kiin
Sending `kiin`
> ull
Sending `ull`
> 
```

Mở file bằng IDA64, chương trình về cơ bản là in ra Thumbnail, sau đó dùng một vòng lặp ``while(1)`` để bắt chúng ta nhập input liên tục rồi đưa input đó vào hàm ``send_satellite_message`` để xử lý

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/d51c86c6-3f4e-4acb-8834-82f90d167778)

Khi debug, mình thấy hàm này là một hàm được lấy từ thư viện ``library.so`` mà challange cung cấp

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/f6ef13d4-23d2-4747-b5b3-4e72adf2d0fe)

Mở ``library.so`` bằng IDA64 và xem qua các hàm của nó, dễ dàng nhận thấy ``send_satellite_message`` chính là hàm dưới đây

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/73601a1c-1c11-4af2-9b47-069953f20432)

Đọc qua hàm và dựa vào giá trị mà hàm truyền vào ở hàm ``main`` của chương trình, dễ nhận thấy chương trình chỉ đơn giản là lặp đi lặp lại việc nối chuỗi chúng ta nhập vào với chuỗi ``START`` được khai báo sẵn rồi sau đó cũng chẳng để làm gì cả???

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/93bba2e0-180c-4917-bf61-35bf777a23a8)

Quay lại ``library.so`` và xref theo hàm ``send_satellite_message``, ta thấy hàm này được gọi bới hàm ``sub_25D0`` như dưới đây. Về cơ bản hàm đang muốn lấy giá trị của biến môi trường ``SAT_PROD_ENVIRONMENT``, nếu giá trị này có tồn tại thì chương trình sẽ chạy vào hàm ``sub_23E3``, còn không thì bỏ qua và chạy tiếp vào ``send_satellite_message``

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/2d763367-6317-46c6-9798-983775913e0f)

Về ``sub_23E3``, sau khi phân tích kĩ mình nhận ra rằng hàm này đầu tiên dựa vào hàm ``sub_21A9`` để lấy địa chỉ của hàm ``read``, sau đó thực hiện hàng loạt các bước biến đổi phức tạp để biến ``byte_11A9`` thành Shellcode, cuối cùng thay địa chỉ của hàm ``read`` thành địa chỉ của các Shellcode vừa được biến đổi xong trên kia

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/67c4bf2f-e339-4dd9-adaf-9b47dd4ed2cc)

Để ý kĩ lại chương trình, chước khi chạy vào vòng lặp kia, chương trình có gọi đến hàm ``_send_satellite_message`` trước, bây giờ khi debug lại và chạy vào nó trước, mình đã vào được hàm xử lý có vẻ giống với hàm  ``sub_25D0``

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/765748ea-72f4-42f4-973a-5bde9459d0f3)

Bây giờ thì mình sẽ SetIP để cho chương trình chắc chắn chạy qua hàm ``sub_23E3``, sau đó quay lại ``main``, đặt breakpoint tại lệnh gọi hàm ``_read`` để trace tới và chạy thẳng vào hàm đó, lúc này chương trình đã nhảy vào các Shellcode được tính trước đó ở ``sub_23E3``

### Phân tích Shellcode

Ấn P để chuyển Shellcode sang dạng hàm, có thể nhìn được cơ bản chương trình sẽ chạy như dưới đây

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/185132c8-065b-498b-816f-6bf83292af41)

Hàm ``syscallLinux`` đơn giản là nhảy tới một hàm gọi syscall như dưới đây, có thể dễ dàng hiểu được hàm này đang yêu cầu chúng ta nhập Input

```C
__int64 __fastcall sub_7FCABB69F121(unsigned int a1)
{
  __int64 result; // rax

  result = a1;
  __asm { syscall; LINUX - }
  return result;
}
```

Vậy có thể hiểu căn bản như sau: Shellcode yêu cầu chúng ta nhập flag, sau đó tiến hành kiểm tra 4 kí tự đầu của flag có phải là ``HTB{`` hay không, những kí tự còn lại sẽ tiếp tục được đưa vào hàm ``checkFlag`` để kiểm tra tiếp

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/74e9f655-43bb-4494-a962-678b1d80259f)

Trên đây là nội dung của hàm ``checkFlag``, dựa vào đó dễ dàng viết được script để lấy flag của challenge

```python
stri = 'l5{0v0Y7fVf?u>|:O!|Lx!o$j,;f'
flag = 'HTB{'
for i in range(28):
    flag += chr(ord(stri[i]) ^ i)
print(flag)
```

# Flag

``HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}``

