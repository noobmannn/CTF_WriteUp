# beehive

Đề cho một file eBPF

![](https://github.com/noobmannn/CTF_WriteUp/blob/2f2dd1e280927d491191769ba7074ecec6e8a6b5/bi0sctf-2024/beehive/img/image.png)

Mở file trên bằng Ghidra (cách để phân tích file eBPF bằng Ghidra xem ở [đây](https://github.com/Nalen98/eBPF-for-Ghidra)) sau đó xem mã giả của hàm ```weird_function```

![](https://github.com/noobmannn/CTF_WriteUp/blob/1f58733384aff18e9ddd88200700725f6c2d53c7/bi0sctf-2024/beehive/img/1.png)

Hàm này thực hiện một vài bước biến đổi nhỏ với biến ```local_58```, sau đó so sánh nó với biến ```puVar5```, nếu sai thì biến boolean ```bVar1``` bị set thành False. Giá trị của biến ```puVar5``` có thể được lấy ở đây

![](https://github.com/noobmannn/CTF_WriteUp/blob/1f58733384aff18e9ddd88200700725f6c2d53c7/bi0sctf-2024/beehive/img/2.png)

Mình sẽ thử dùng z3 để viết script lấy giá trị của ```local_58```

```python
from z3 import *

local_58 = [BitVec('local_58_%d' % i, 8) for i in range(29)]
puVar5 = [0x56, 0xae, 0xce, 0xec, 0xfa, 0x2c, 0x76, 0xf6, 0x2e, 0x16, 0xcc, 0x4e, 0xfa, 0xae, 0xce, 0xcc, 0x4e, 0x76, 0x2c, 0xb6, 0xa6, 0x2, 0x46, 0x96, 0xc, 0xce, 0x74, 0x96, 0x76]
solver = Solver()

for i in range(29):
    uVar8 = (local_58[i] & 0xf0) >> 4 | (local_58[i] & 0xf) << 4
    uVar8 = uVar8 >> 2 & 0x33 | (uVar8 & 0x33) << 2
    uVar8 = uVar8 >> 1 & 0x55 | (uVar8 & 0x55) << 1
    solver.add(uVar8 == puVar5[i])

if solver.check() == sat:
    model = solver.model()
    result = [model[local_58[i]].as_long() for i in range(29)]
    flag = 'bi0sctf{'
    for c in result:
        flag += chr(c)
    flag += '}'
    print(flag)
else:
    print("Fail!")
```

Kết quả của đoạn Script trên là Flag của bài

# Flag

```bi0sctf{jus7_4noth3r_us3rn4me@bi0s.in}```
