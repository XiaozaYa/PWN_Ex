A = sys_number
A == 257? e:next
A == 1? r:next
return ALLOW
e:
return ERRNO(0)
r:
return ALLOW
