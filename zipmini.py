#! /usr/bin/python
import sys
import os
import struct
import zlib
import binascii
lrecords=0
crecords=0
cdsfirst=0
offsets=dict()
def decompress_data(r, csz=None):
   cbytes=0
   dbytes=0
   acrc = 0
   do = zlib.decompressobj(-zlib.MAX_WBITS)
   while True:
      if csz is not None and csz < 1024:
         nb = csz
      else:
         nb = 1024
      byte=r.read(nb)
      if byte is None:
         raise ValueError, "file format error: file truncated (compressed data)"
      #print "Read {0} bytes (of {1})".format(len(byte), nb)
      #print binascii.hexlify(byte)
      out=do.decompress(byte)
      if out is not None and len(out) > 0:
         acrc = zlib.crc32(out, acrc)
         dbytes = dbytes + len(out)
      if do.unused_data is not None and len(do.unused_data) > 0:
         cbytes = cbytes + len(byte) - len(do.unused_data)
         if csz is not None:
            csz = csz - len(byte) + len(do.unused_data)
            raise ValueError, "file format error: end of compressed stream reached, but {0} bytes are left to consume".format(csz)
         break
      cbytes = cbytes + len(byte)
      if csz is not None:
         csz = csz - len(byte)
         #print "{0} bytes remaining for this file".format(csz)
         if csz == 0:
            break
   if csz is None:
      #print "used {0} bytes. Need to seek back {1} bytes. offset is {2}".format(cbytes, len(do.unused_data), r.tell())
      r.seek(0 - len(do.unused_data), 1)
   return (acrc, cbytes, dbytes)

with file(sys.argv[1], "rb") as r:
    while True:
        curofs=r.tell()
        data=r.read(4)
        if data is None or len(data) == 0:
            break
        (hdr1,hdr2,hdr3)=struct.unpack("<2sbb", data)
        if hdr1 == "PK" or hdr1 == "AB":
            islr = False
            if hdr2 == 3 and hdr3 == 4: # local record
               data=r.read(26)
               (ver,gpf,mthd,mt,md,crc,csz,dsz,fsz,fldlen)=struct.unpack("<HHHHHIIIHH", data)
               vp = ver >> 8
               if vp > 0x20:
                  print >>sys.stderr, "requires new ZIP features ({0}.{1})".format(vp >> 4, vp & 0xf)
               if mthd != 0 and mthd != 8:
                  print >>sys.stderr, "unsupported compression {0}".format(mthd)
               islr = True
               if gpf & (1 << 3):
                  if csz != 0 or dsz != 0 or crc != 0:
                     raise ValueError, "size or crc present when should not be: ({0}, {1}, {2})".format(csz, dsz, crc)
                  if mthd != 8:
                     raise ValueError, "Must use deflate when compressed size not known"
                  if gpf & (1 << 0):
                     raise ValueError, "Cannot use encryption when compressed size not known"
                  if gpf & (1 << 4):
                     raise ValueError, "Cannot use Deflate64 when compressed size not known"
               if (gpf & ~((1<<3) | (1<<11))) != 0:
                  print >>sys.stderr, "Unsupported flag bits {0}".format(gpf)
                  #raise ValueError, "Unsupported flag bits"
            elif hdr2 == 1 and hdr3 == 2: # central directory record
                if cdsfirst == 0:
                    print "CDS found at {}".format(curofs)
                    cdsfirst=curofs
                data=r.read(42)
                (v1,v2,gpf,mthd,mt,md,crc,csz,dsz,fsz,fldlen,cmntlen,dk,inat,extat,ofs)=struct.unpack("<HHHHHHIIIHHHHHII", data)
            elif hdr2 == 5 and hdr3 == 6: # end of central directory
                data=r.read(18)
                (dsk,sdsk,tent,allent,dirsz,cdsofs,cmntsz)=struct.unpack("<HHHHIIH",data)
                print "End of CDS found at {}".format(curofs)
                
                cmnt=r.read(cmntsz)
                print "Processed {0} local records, {1} central directory records".format(lrecords, crecords)
                for fn in offsets:
                    print "Local record for {0}; not found in CDS".format(fn)
                continue
            else:
                print "Current offset is ", r.tell()-4
                raise ValueError, "file format error or misalignment (ZIPTYPE = {0}{1})".format(hdr2, hdr3)
                
        else:
            print "Current offset is ", r.tell()-4
            raise ValueError, "file format error or misalignment (hdr1)" + hdr1
            
        s=os.fstat(r.fileno())
        if s.st_size < r.tell() + fsz:
           raise ValueError, "file format error: file truncated (filename)"
        fn=r.read(fsz)
        if fn is None:
            raise ValueError, "file format error: EOF instead of filename"
        if len(fn) != fsz:
            raise ValueError, "file format error: short read of filename"
        if s.st_size < r.tell() + fldlen:
            raise ValueError, "file format error: file truncated (extra data)"
        r.seek(fldlen, 1)
        if islr:
            lrecords+=1
            if gpf & (1 << 3):
               (acrc, cbytes, dbytes)=decompress_data(r)
               ddesch = r.read(4)
               if len(ddesch) != 4:
                     raise ValueError, "file format error: file truncated (data descriptor signature)"
               (hdr1,hdr2,hdr3)=struct.unpack("<2sbb", ddesch)
               if hdr1 == 'PK' and hdr2 == 7 and hdr3 == 8:
                  #print "Data descriptor header found"
                  pass
               else:
                  r.seek(-4, 1)
               ddesc = r.read(12)
               if len(ddesc) != 12:
                     raise ValueError, "file format error: file truncated (data descriptor)"
               (crc, csz, dsz)=struct.unpack("<III", ddesc)
               if dsz > 0 and acrc is None:
                  print "CRC mismatch: Actual {0}, expected {1}".format(None, crc)
               elif acrc is None:
                  pass
               elif acrc & 0xffffffff != crc:
                  print "CRC mismatch: Actual {0}, expected {1}".format(acrc & 0xffffffff, crc)
               if cbytes != csz:
                  print "Compressed size mismatch: Actual {0}, expected {1}".format(cbytes, csz)
               if dbytes != dsz:
                  print "File size mismatch: Actual {0}, expected {1}".format(dbytes, dsz)
            elif mthd == 8 and gpf == 0:
               (acrc, cbytes, dbytes)=decompress_data(r, csz)
               if dsz > 0 and acrc is None:
                  print "CRC mismatch: Actual {0}, expected {1}".format(None, crc)
               elif acrc is None:
                  pass
               elif acrc & 0xffffffff != crc:
                  print "CRC mismatch: Actual {0}, expected {1}".format(acrc & 0xffffffff, crc)
               if cbytes != csz:
                  print "Compressed size mismatch: Actual {0}, expected {1}".format(cbytes, csz)
               if dbytes != dsz:
                  print "File size mismatch: Actual {0}, expected {1}".format(dbytes, dsz)
            else:
               if s.st_size < r.tell() + csz:
                  raise ValueError, "file format error: file truncated (compressed data)"
               r.seek(csz, 1)
            offsets[fn]=curofs
            print "{0}->{1} bytes of {2}".format(csz, dsz, fn)
        else:
            crecords+=1
            if fn in offsets:
                if offsets[fn] != ofs:
                    print "CDS offset for {0} points to {1}, found at {2}".format(fn, cdsofs, offsets[fn])
                del offsets[fn]
            else:
                print "CDS offset for {0} points to {1}, not found in file".format(fn, cdsofs)
    
