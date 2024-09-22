# t8

Challenge cho một file PE32 ``t8.exe`` và một file pcap ``traffic.pcapng``

![image](https://github.com/user-attachments/assets/f2a19dee-1ed5-4258-81e0-25d9b6c4060a)

Mở chương trình bằng IDA và xem hàm ``main`` thì ngay đầu tiên ta cần phải bypass lại hàm sau

```C
  while ( sub_404570(xmmword_45088C, DWORD1(xmmword_45088C), DWORD2(xmmword_45088C), HIDWORD(xmmword_45088C)) != 15 )
    Sleep(0x2932E00u);
```

Xem qua hàm ``sub_404570`` 

```C
int __cdecl sub_404570(unsigned int a1, unsigned int a2)
{
  unsigned int v2; // ecx
  int v3; // esi
  unsigned int v4; // eax
  float v5; // xmm0_4
  float v9; // [esp+2Ch] [ebp+14h]

  v2 = HIWORD(a1);
  v3 = (unsigned __int16)a1 - 1;
  if ( HIWORD(a1) > 2u )
    v3 = (unsigned __int16)a1;
  v4 = v2 + 12;
  if ( v2 > 2 )
    v4 = HIWORD(a1);
  v9 = (float)((float)((double)(int)(v3 / 100 / 4
                                   + HIWORD(a2)
                                   + (int)((double)(v3 + 4716) * 365.25)
                                   - (int)((double)(int)(v4 + 1) * -30.6001)
                                   - v3 / 100
                                   + 2)
                     - 1524.5)
             - 2451549.5)
     / 29.53;
  v5 = floor(v9);
  return (int)roundf((float)(v9 - v5) * 29.53);
}
```

Thử Search trên google thì mình nhận ra mấy công thức này có vẻ liên quan đến tính toán chu kì của Mặt Trăng ???

Để bypass thì ta chỉ đơn giản là Patch lại chương trình bằng cách sửa lệnh ``jz`` thành ``jnz`` như dưới đây

![image](https://github.com/user-attachments/assets/7a634fa8-b95d-47cd-86eb-0d5c3337c827)

Phần tiếp theo của chương trình chỉ là Xor một vài đoạn data cố định để tạo chuỗi widechar ``flare-on.com``

```C
  memset(v45, 0, sizeof(v45));
  *(_QWORD *)Block = 0x7C007E0072003Fi64;
  memset(v46, 0, sizeof(v46));
  v3 = 8;
  v43 = _mm_xor_si128((__m128i)xmmword_93B980, (__m128i)xmmword_93B884);
  do
    v43.m128i_i16[v3++] ^= 0x11u;               // flare-on.com
  while ( v3 < 0xC );
  v36[4] = 0;
  v37 = 7;
  LOWORD(v36[0]) = 0;
  maybeCPY(v36, &v43, wcslen((const unsigned __int16 *)&v43));
```

Sau đó chương trình khởi tạo thêm vùng nhớ, rồi vào ``sub_4034C0`` để khởi tạo struct

![image](https://github.com/user-attachments/assets/3391cfcc-2101-451b-8c57-21045ed07cc9)

Để tiện theo dõi thì mình sẽ tạo một struct như dưới

```C
struct thiss
{
  struct struc_D4B918 *vftable;
  BYTE methodHTTP[16];
  DWORD flareondotcom;
  BYTE sus1[12];
  DWORD is0xC;
  DWORD is0xF;
  DWORD hashMD5pointer;
  BYTE sus2[20];
  DWORD DataResponePointer;
  DWORD isunk;
};
```

Lúc này mã giả sẽ trông như dưới đây

```C
thiss *__thiscall initStruct(thiss *this, _DWORD *Block, int a3, int a4, int a5, int a6, unsigned int a7)
{
  _DWORD **p_Block; // eax
  void *v9; // eax
  char *v10; // ecx

  this->vftable = (struct struc_D4B918 *)&CClientSock::`vftable';
  *(_WORD *)this->methodHTTP = 0;
  *(_QWORD *)&this->methodHTTP[2] = 0i64;
  *(_DWORD *)&this->methodHTTP[10] = 0;
  *(_WORD *)&this->methodHTTP[14] = 0;
  this->is0xC = 0;
  this->is0xF = 7;
  LOWORD(this->flareondotcom) = 0;
  *(_DWORD *)&this->sus2[12] = 0;
  *(_DWORD *)&this->sus2[16] = 7;
  LOWORD(this->hashMD5pointer) = 0;
  p_Block = &Block;
  if ( &this->flareondotcom != (DWORD *)&Block )
  {
    if ( a7 >= 8 )
      p_Block = (_DWORD **)Block;
    maybeCPY((void **)&this->flareondotcom, p_Block, a6);
  }
  v9 = (void *)unknown_libname_56(2048);
  this->DataResponePointer = (DWORD)v9;
  memset(v9, 0, 0x800u);
  if ( a7 >= 8 )
  {
    v10 = (char *)Block;
    if ( 2 * a7 + 2 >= 0x1000 )
    {
      v10 = (char *)*(Block - 1);
      if ( (unsigned int)((char *)Block - v10 - 4) > 0x1F )
        _invalid_parameter_noinfo_noreturn();
    }
    free(v10);
  }
  return this;
}
```

Quay trở lại với hàm ``main``, chương trình tạo chuỗi ``POST`` dạng widechar rồi đẩy vào ``thiss->methodHTTP``

```C
  LOBYTE(v52) = 0;
  thissCpy0 = thiss;
  v47 = 0x540053004F0050i64;
  v48 = 0;
  v49 = 0;
  v50 = 0;
  v51 = 0;
  vftable = thiss->vftable;
  thissCpy1 = thissCpy0;
  ((void (__thiscall *)(thiss *, __int64 *))vftable->moveStr)(thissCpy0, &v47);
```

Phần tiếp theo sẽ chuyển giá trị tại ``dword_940870`` thành dạng thập phân rồi nối vào sau chuỗi ``flare-on.com``, sau đó lại nối giá trị dạng thập phân của ``dword_940870`` với giá trị của ``dword_940874``

```C
v8 = convertWidechar1(Block, dword_940870);   // .com->7271
  LOBYTE(v52) = 2;
  v9 = v8;
  v10 = (unsigned int)v8[5] < 8;
  Src = v8;                                     // Src = 7271
  if ( !v10 )
  {
    v9 = *v8;
    Src = *v8;
  }
  v11 = (unsigned int)v8[4];
  v12 = dword_940884;
  if ( v11 > dword_940888 - dword_940884 )
  {
    LOBYTE(Src) = 0;
    v15 = sub_8F5CF0((const void **)aFo97271, v11, (int)Src, v9, v11);
  }
  else
  {
    v13 = aFo97271;
    v14 = dword_940884 + v11;
    if ( (unsigned int)dword_940888 >= 8 )
      v13 = (void **)aFo97271[0];
    dword_940884 += v11;
    memmove_0((char *)v13 + 2 * v12, Src, 2 * v11);
    *((_WORD *)v13 + v14) = 0;
    v15 = (const void **)aFo97271;
    thissCpy0 = thissCpy1;
  }
  maybeMemmove(&v30, v15);
```

Hai giá trị trên được khởi tạo tại hàm ``sub_8F1020``, với ``dword_940874`` là chuỗi ``FO9`` còn ``dword_940870`` là một số ngẫu nhiên được gen ra bằng hàm ``rand()``, ví dụ nếu giá trị của ``dword_940870`` là ``7271`` thì ta có chuỗi ``FO97271``

![image](https://github.com/user-attachments/assets/ffa20a1f-b270-42a0-ab23-d57c0c5ed2ff)

Tiếp theo chương trình chạy vào hàm ``sub_8F37A0``, dựa vào debug thì có thể chương trình đang hash chuỗi ``FO97271`` bằng một thuật toán hash giống với md5 và đẩy vào trong ``thiss->hashMD5Pointer``

```C
void __thiscall sub_8F37A0(thiss *this, _DWORD *Block, int a3, int a4, int a5, int a6, unsigned int a7)
{
  _DWORD **p_Block; // edx
  char *v9; // esi
  char *v10; // ecx
  __int16 v11; // dx
  char *v12; // ecx

  p_Block = &Block;
  if ( a7 >= 8 )
    p_Block = (_DWORD **)Block;
  v9 = (char *)this->vftable->maybeHashMD5(p_Block);
  v10 = v9;
  do
  {
    v11 = *(_WORD *)v10;
    v10 += 2;
  }
  while ( v11 );
  maybeCPY((void **)&this->hashMD5pointer, v9, (v10 - (v9 + 2)) >> 1);
  j_j__free(v9);
  if ( a7 >= 8 )
  {
    v12 = (char *)Block;
    if ( 2 * a7 + 2 >= 0x1000 )
    {
      v12 = (char *)*(Block - 1);
      if ( (unsigned int)((char *)Block - v12 - 4) > 0x1F )
        _invalid_parameter_noinfo_noreturn();
    }
    free(v12);
  }
}
```

Phần tiếp theo của chương trình chỉ là tạo một chuỗi widechar cố định ``ahoy``

```C
  *(_QWORD *)v45 = 0x79006F00680061i64;
  *(_WORD *)&v45[8] = 0;
  v45[10] = 0;
  memset(v46, 0, sizeof(v46));
  v38[4] = 0;
  v39 = 7;
  LOWORD(v38[0]) = 0;
  maybeCPY(v38, v45, wcslen((const unsigned __int16 *)v45));// ahoy
  v29 = 1;
  LOBYTE(v52) = 3;
  maybeMemmove(&v28, v38);                      // ahoy
```

Tiếp theo chương trình chạy vào hàm ``sub_403D70`` để thực hiện giao thức HTTP, để thuận tiện phân tích thì mình đổi tên hàm này thành ``sendDataHTTP``

### Giao thức HTTP

Tiến hành phân tích hàm ``sendDataHTTP``, đầu tiên hàm này mã hoá RC4 chuối ``ahoy`` mới key là hash của chuỗi ``FO97271``, sau đó tiếp tục Encrypt Base64 kết quả

```C
  v49 = 0;
  v9 = 2 * a6;
  v35 = (LPDWORD)(2 * a6);
  p_Block = &Block;
  if ( a7 >= 8 )
    p_Block = (_DWORD **)Block;
  v34 = p_Block;
  maybeMemmove(v33, &this->hashMD5pointer);
  v11 = ((int (__thiscall *)(thiss *, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, HINTERNET, LPDWORD))this->vftable->rc4)(
          this,
          v33[0],
          v33[1],
          v33[2],
          v33[3],
          v33[4],
          v33[5],
          v34,
          v35);                                 // rc4, key la hash, plaintext la widechar 'ahoy'
  this->vftable->base64encode((int)this, (int)lpOptional, v11, v9);
```

Tiếp theo, chương trình gọi hàm ``ObtainUserAgentString`` để lấy ``user-agent``, sau đó nối chuỗi số ngẫu nhiên mà chương trình gen ra trước đó nối vào sau User-Agent, trong trường hợp của mình là ``7271``

```C
  if ( ObtainUserAgentString(0, pszUAOut, &cbSize) )
  {
    if ( v45 >= 8 )
    {
      v13 = lpOptional[0];
      v14 = (DWORD *)(2 * v45 + 2);
      if ( (unsigned int)v14 >= 0x1000 )
      {
        v13 = (void *)*((_DWORD *)lpOptional[0] - 1);
        v14 = (DWORD *)(2 * v45 + 37);
        if ( (unsigned int)(lpOptional[0] - v13 - 4) > 0x1F )
          goto LABEL_50;
      }
      v35 = v14;
      free(v13);
    }
    v44 = 0;
    v45 = 7;
    LOWORD(lpOptional[0]) = 0;
    if ( a7 < 8 )
      return 0;
    v15 = Block;
    v16 = (DWORD *)(2 * a7 + 2);
    if ( (unsigned int)v16 < 0x1000
      || (v15 = (_DWORD *)*(Block - 1),
          v16 = (DWORD *)(2 * a7 + 37),
          (unsigned int)((char *)Block - (char *)v15 - 4) <= 0x1F) )
    {
      v35 = v16;
      free(v15);
      return 0;
    }
LABEL_50:
    _invalid_parameter_noinfo_noreturn();
  }
  if ( cbSize - 2 >= 0x200 )
  {
    __report_rangecheckfailure();
    goto LABEL_50;
  }
  v18 = dword_940870;
  pszUAOut[cbSize - 2] = 0;
  convertWidechar1((void **)Source, v18);
  mbstowcs_s(&PtNumOfCharConverted, DstBuf, 0x200u, pszUAOut, strlen(pszUAOut));
  wcscat_s(DstBuf, 0x200u, L"; ");
  if ( a8 )
  {
    v19 = (const wchar_t *)Source;
    if ( v41 >= 8 )
      v19 = Source[0];
  }
  else
  {
    v19 = L"CLR";
  }
  wcscat_s(DstBuf, 0x200u, v19);
  wcscat_s(DstBuf, 0x200u, L")");
```

Tiếp theo sau chương trình gọi hàng loạt các API liên quan đến xử lý gói tin HTTP như ``WinHttpOpen``, ``WinHttpConnect``, ``WinHttpOpenRequest``, ``WinHttpSendRequest``, ``WinHttpReceiveResponse``, ``WinHttpQueryDataAvailabl``, ``WinHttpReadData``, ... Đọc qua đoạn code tiếp theo cũng có thể thấy chương trình đang tạo kết nối HTTP tới host là ``flare-on.com``, với method là ``POST``

```C
  v20 = WinHttpOpen(DstBuf, 0, 0, 0, 0);        // noi number random vao chuoi user agent
  v37 = v20;
  if ( v20 )
  {
    p_flareondotcom = (const WCHAR *)&this->flareondotcom;
    if ( this->is0xF >= 8 )
      p_flareondotcom = *(const WCHAR **)p_flareondotcom;
    v22 = (void (__stdcall *)(HINTERNET))WinHttpCloseHandle;
    v23 = WinHttpConnect(v20, p_flareondotcom, 0x50u, 0);
    hInternet = v23;
    if ( v23 )
    {
      v24 = WinHttpOpenRequest(v23, (LPCWSTR)this->methodHTTP, 0, 0, 0, 0, 0);
```

Lúc này quay qua phân tích file ``traffic.pcapng`` bằng wireshark và đọc gói tin như dưới đây, có thể thấy chương trình dùng phương thức POST để gửi đến host gồm chuỗi user-agent có chứa giá trị random và chuỗi ``ahoy`` đã bị mã hoá bằng RC4 và base64, sau đó host sẽ trả về một chuỗi base64 khác như hình dưới

![image](https://github.com/user-attachments/assets/a1688ed1-5470-461c-b625-a0aa2cfbe45b)


