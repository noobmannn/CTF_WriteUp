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

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/2cb4ebc3-457a-4abe-96ce-b5747b33515d)

Quay lại ``library.so`` và xref theo hàm ``send_satellite_message``, ta thấy hàm này được gọi bới hàm ``sub_25D0`` như dưới đây. Về cơ bản hàm đang muốn lấy giá trị của biến môi trường ``SAT_PROD_ENVIRONMENT``, nếu giá trị này có tồn tại thì chương trình sẽ chạy vào hàm ``sub_23E3``, còn không thì bỏ qua và chạy tiếp vào ``send_satellite_message``

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/2d763367-6317-46c6-9798-983775913e0f)

### Phân tích hàm sub_23E3

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/90f8dfb4-140e-4c5f-8ca8-2042d11e0076)

Đầu tiên chương trình gọi hàm ``getauxval`` với tham số truyền vào là 0x3 (tương đương với Enum ``AT_PHDR``). Hàm này nhằm được sử dụng để truy xuất các giá trị từ vector phụ trợ (auxiliary vector), đây là một phần của môi trường tiến trình cung cấp các thông tin khác nhau về tiến trình cho kernel và hệ thống. Với tham số là ``AT_PHDR``, hàm này trả về địa chỉ của program headers trong tiến trình. Đây là một mảng các cấu trúc Elf32_Phdr hoặc Elf64_Phdr, tùy thuộc vào kiến trúc của hệ thống (32-bit hoặc 64-bit). Ở trường hợp của bài là mảng các cấu trúc Elf64_Phdr. 

Tiếp theo chương trình gọi đến hàm ``sub_21A9``

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/2d0f27d6-3749-441e-a79f-58cfb95af72e)

Đầu tiên hàm thực hiện một vòng lặp phức tạp như dưới đây

```C
  phdrs = (Elf64_Phdr *)((char *)hdr + hdr->p_filesz);
  symtab = 0LL;
  jmprel = 0LL;
  strtab = 0LL;
  for ( i = 0; i < LOWORD(hdr[1].p_type); ++i )
  {
    if ( phdrs[i].p_type == PT_DYNAMIC )
    {
      for ( j = (Elf64_Dyn *)((char *)hdr + phdrs[i].p_offset); j->d_tag; ++j )
      {
        switch ( j->d_tag )
        {
          case DT_SYMTAB:
            symtab = (Elf64_Sym *)((char *)hdr + j->d_un);
            break;
          case DT_STRTAB:
            strtab = (char *)hdr + j->d_un;
            break;
          case DT_JMPREL:
            jmprel = (Elf64_Rela *)((char *)hdr + j->d_un);
            break;
        }
      }
    }
  }
  if ( !symtab || !strtab || !jmprel )
    return 0LL;
```

Vòng lặp này nhằm làm những việc sau:
- Đầu tiên duyệt qua toàn bộ các mảng cấu trúc Elf64_Phdr để tìm mảng có type là ``PT_DYNAMIC``, đây là một loại entry trong bảng Program Header Table, được sử dụng để mô tả một segment động. Segment này chứa các thông tin cần thiết cho quá trình liên kết động (dynamic linking), như các thư viện động cần thiết, các bảng con trỏ, các bảng băm (hash tables), và các thông tin khác.
- Sau khi tìm thấy mảng cấu trúc cần thiết, chương trình tiếp tục thực hiện duyệt toàn bộ mảng trên để tìm cấu trúc Elf_Dyn có giá trị ``d_tag`` là ``DT_SYMTAB`` sau đó lưu địa chỉ của nó vào ``symtab``. Đây chính là con trỏ trỏ đến toàn bộ các ``symbol``, tức là toàn bộ các tên hàm trong file Elf. Tương tự với hai case còn lại là ``DT_STRTAB`` - chứa địa chỉ của bảng chuỗi, được lưu vào ``strtab`` và ``DT_JMPREL`` - chứa địa chỉ của bảng các PLT - Procedure Linkage Table, bảng này chứa các con trỏ trỏ đến địa chỉ các hàm, được lưu vào ``jmprel``

```C
  v4 = -1;
  for ( k = 0; &symtab[k] < (Elf64_Sym *)strtab; ++k )
  {
    v11 = &symtab[k];
    if ( v11->st_name && !strcmp(&strtab[v11->st_name], name) )
    {
      v4 = k;
      break;
    }
  }
  if ( v4 < 0 )
    return 0LL;
  while ( jmprel->r_offset )
  {
    if ( HIDWORD(jmprel->r_info) == v4 )
      return (__int64)hdr + jmprel->r_offset;
    ++jmprel;
  }
  return 0LL;
}
```

Phần còn lại của hàm thực hiện hai vòng lặp:
- Duyệt toàn bộ mảng ``symtab``, đối với mỗi giá trị, chúng ta xác định tên của nó dựa theo bảng ``strtab`` rồi so sánh với giá trị ``name`` được truyền vào, trong trường hợp cụ thể của chúng ta là tên hàm ``read``. Nếu tìm thấy thì trả về k và lưu nó vào v4
- Tiếp theo hàm duyệt tiếp qua bảng ``jmprel``, nếu tìm thấy giá trị nào có ``r_info`` trùng với v4, chương trình sẽ trả về địa chỉ của hàm cần tìm.

Tổng kết lại, mục đích của hàm ``sub_21A9`` nhằm tìm địa chỉ của hàm có tên được chỉ định. Ở đây là hàm ``read``

Quay lại hàm ``sub_23E3``, sau khi tìm được địa chỉ hàm ``read``, về cơ bản chương trình sao chép toàn bộ byte của ``byte_11A9`` vào biến ``dest`` rồi gọi hàm ``memfrob``, hàm này đơn giản chỉ là xor từng byte của ``byte_11A9`` với ``0x2A``. Kết quả thu được là một đoạn Shellcode. Sau đó ghi đè toàn bộ đoạn Shellcode trên vào hàm ``read`` như ở dưới. 

```C
  dest = mmap(0LL, (((char *)sub_21A9 - (char *)byte_11A9) & 0xFFFFFFFFFFFFF000LL) + 4096, 7, 34, -1, 0LL);
  memcpy(dest, byte_11A9, (char *)sub_21A9 - (char *)byte_11A9);
  memfrob(dest, (char *)sub_21A9 - (char *)byte_11A9);
  result = readFuncAddr;
  *readFuncAddr = dest;
```

Bây giờ ta quay lại file ``satelitte``. Để ý kĩ lại chương trình, trước khi chạy vào vòng lặp kia, chương trình có gọi đến hàm ``_send_satellite_message`` trước, bây giờ khi debug lại và chạy vào nó trước, mình đã vào được hàm xử lý có vẻ giống với hàm  ``sub_25D0``

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/765748ea-72f4-42f4-973a-5bde9459d0f3)

Bây giờ thì mình sẽ SetIP để cho chương trình chắc chắn chạy qua hàm ``sub_23E3``, sau đó quay lại ``main``, đặt breakpoint tại lệnh gọi hàm ``_read`` để trace tới và chạy thẳng vào hàm đó, lúc này chương trình đã nhảy vào các Shellcode được tính trước đó ở ``sub_23E3``

![image](https://github.com/noobmannn/CTF_WriteUp/assets/102444334/962ea5fb-13d3-4ef8-94b6-da8df6d651b9)

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

