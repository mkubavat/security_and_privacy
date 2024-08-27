To compile under 32 bits, use -m32: 

g++ test.c -m32 -g3 -o test

-g3 enables debug information for gdb.

test-weak.c is the easier version checking authorized != 0.
test.c is the second version checking authorized == 1. 

txtwrite.py attempts to overwrite ffffcd80 if the username string is located at the 61st argument after printf. 

txtwrite2.py overwrites:

ffffcd80: 0x101
ffffcd81: 0x200
ffffcd82: 0x300
ffffcd83: 0x400

The combined effect is to overwrite the 5 bytes at ffffcd80 with 400000001, which resolves to 1 due to integer overflow. 

To run under gdb and examine memory:

gdb --args test hackuser.txt

Some useful gdb commands:

break <line number> - sets a breakpoint at the line number
print authorized - prints the value of authorized
print &authorized - prints the address of authorized 
run - runs the code up to next breakpoint
n - run the next line
info frame - show the current rfame
x/80x $esp - print 80 words as hexadecimals from the current stack top ($esp)

Note that gdb disables ASLR, which is why our attack always works under gdb. With ASLR, this attack would only have a chance of working. Practically, an attacker could break ASLR by first using a username to map out the address space, then use a second username to break in, but that would not work against our sample code because it does not read more than one username per execution.


