"""
sorry i can't solve it
"""
from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
context.terminal = ['tmux', 'splitw', '-h']
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
menu   = b'Your choice:'

def add(cont):
	sla(menu, b'1')
	sla(b'item:', cont)

def show(idx):
	sla(menu, b'2')
	sla(b'Index:', byte(idx))

def edit(idx, cont):
	sla(menu, b'3')
	sla(b'Index:', byte(idx))
	sla(b'content:', cont)

def bubble(idx, flag=1):
	sla(menu, b'4')
	sla(b'East)', byte(flag))
	sla(b'index:', byte(idx))

def dele():
	sla(menu, b'5')

debug()
add(b'1'*0x18)
debug()
add(b'2'*0x18)
debug()
add(b'3'*0x18)
debug()
add(b'4'*0x30)

debug()
bubble(2)
debug()
edit(3, p64(0)*2)
debug()
bubble(2)
debug()
show(3)


debug()
sh()


