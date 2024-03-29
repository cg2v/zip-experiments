#! /usr/bin/python
import sys
import os
import struct
import zlib
import binascii
lrecords=0
crecords=0
cdsfirst=0
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

def scan_cds(r):
   r.seek(-1024, 2)
   buf=r.read()
   if buf is None or len(buf) < 22:
      raise ValueError, "File too short to hold end-of-cds record"
   
   for i in xrange(0,len(buf)-21):
      testb=buf[i:i+4]
      sig=struct.unpack("I", testb)
      if sig[0] == 0x06054b50:
         r.seek(i-len(buf), 2)
         return True
      #print hex(sig[0])
   raise ValueError, "End of Central Directory not found"
   
def compare(v1, v2, label):
   if v1 != v2 and v2 != 0:
      raise ValueError, "Field {0} differs between central directory and local header: {1} vs {2}".format(label, v1, v2)
   
with file(sys.argv[1], "rb") as r:
   ret=scan_cds(r)
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
            (lver,lgpf,lmthd,lmt,lmd,lcrc,lcsz,ldsz,fsz,fldlen)=struct.unpack("<HHHHHIIIHH", data)
            compare(ver, lver, "version")
            compare(gpf, lgpf, "flags")
            compare(mthd, lmthd, "method")
            compare(mt, lmt, "modtime")
            compare(md, lmd, "moddate")
            compare(crc, lcrc, "crc")
            compare(csz, lcsz, "c-size")
            compare(dsz, ldsz, "d-size")
            vp = ver >> 8
            if vp > 0x20:
               print >>sys.stderr, "requires new ZIP features ({0}.{1})".format(vp >> 4, vp & 0xf)
            if mthd != 0 and mthd != 8:
               print >>sys.stderr, "unsupported compression {0}".format(mthd)
            islr = True
            if (gpf & ~((1<<3) | (1<<11))) != 0:
               print >>sys.stderr, "Unsupported flag bits {0}".format(gpf)
               #raise ValueError, "Unsupported flag bits"
         elif hdr2 == 1 and hdr3 == 2: # central directory record
            if cdsfirst == 0:
               print "CDS found at {}".format(curofs)
               cdsfirst=curofs
            data=r.read(42)
            (v1,ver,gpf,mthd,mt,md,crc,csz,dsz,fsz,fldlen,cmntlen,dsk,inat,extat,ofs)=struct.unpack("<HHHHHHIIIHHHHHII", data)
         elif hdr2 == 5 and hdr3 == 6: # end of central directory
            data=r.read(18)
            (thisdsk,dsk,tent,allent,dirsz,cdsofs,cmntsz)=struct.unpack("<HHHHIIH",data)
            print "End of CDS found at {}".format(curofs)
            
            cmnt=r.read(cmntsz)
            if cdsfirst:
               print "Processed {0} local records, {1} central directory records".format(lrecords, crecords)
            else:
               if (dsk == thisdsk):
                  r.seek(cdsofs, 0)
               else:
                  print "The Central directory does not begin on this disk"
                  break
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
         if mthd == 8 and (gpf & ~((1<<3) | (1<<11))) == 0:
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
         print "{0}->{1} bytes of {2}".format(csz, dsz, fn)
         r.seek(seekback)
      else:
         crecords+=1
         if (dsk == thisdsk):
            seekback=r.tell()
            r.seek(ofs)
         else:
            print "File {0} is not present on this disk".format(fn)
    
