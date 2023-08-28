from pwn import *

s = "void fight(int m)"
print(s)
s = "void Exp{}(int m);"
for i in range(256):
	print(s.format(str(i).zfill(3)))

s = "void gamestart(){"
print(s)

s = "	Exp{}(0);"
for i in range(241):
	print(s.format(str(i).zfill(3)))
	
s = "	fight(0);\n}"
print(s)
