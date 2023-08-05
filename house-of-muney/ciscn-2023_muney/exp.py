from pwn import *
context.terminal = ['tmux', 'splitw', '-h' ]
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
context.log_level = 'debug'

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
menu   = b'HTTP_Parser> '
def add(size, con=b'A'*0x10):
	pay = b'POST /create HTTP/1.0\n\rSize:'+byte(size)+b'\nContent-Length:'+byte(len(con))+b'\n\r\n'+con
	sda(menu, pay)

add(0x150000)
debug()
sh()
