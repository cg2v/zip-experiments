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
   r.seek(-3072, 2)
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

def compare_headers(hdr1, hdr2):
   compare(hdr1.version, hdr2.version, "version")
   compare(hdr1.flags, hdr2.flags, "flags")
   compare(hdr1.method, hdr2.method, "method")
   compare(hdr1.time, hdr2.time, "modtime")
   compare(hdr1.date, hdr2.date, "moddate")
   compare(hdr1.crc, hdr2.crc, "crc")
   compare(hdr1.csize, hdr2.csize, "c-size")
   compare(hdr1.size, hdr2.size, "d-size")


class fileHeader(object):
   
   def __init__(self):
      self.safe_flags = False
      self.tested = False
   def postinit(self, fd):
      self.filename = fd.read(self.namelen)
      if self.filename is None:
         raise IOError, "file format error: EOF instead of filename"
      if len(self.filename) != self.namelen:
         raise IOError, "file format error: short read of filename"
      fd.seek(self.fldlen, 1)      
      
   def validate_features(self):
      vp = self.version >> 8
      if vp > 0x20:
         print >>sys.stderr, "requires new ZIP features ({0}.{1})".format(vp >> 4, vp & 0xf)
      if self.method != 0 and self.method != 8:
         print >>sys.stderr, "unsupported compression {0}".format(self.method)
      if (self.flags & ~((1<<3) | (1<<11))) != 0:
         print >>sys.stderr, "Unsupported flag bits {0}".format(self.flags)
      else:
         self.safe_flags = True
               
               
class cdsHeader(fileHeader):
   
   def __init__(self, fd):
      super(cdsHeader, self).__init__()
      self.is_local = False
      data=fd.read(42)
      if data is None or len(data) != 42:
         raise IOError, "file truncated or bad offset (cds entry)"
      (self.writeversion, self.version,
       self.flags, self.method, self.time, self.date,
       self.crc, self.csize, self.size, self.namelen, 
       self.fldlen,self.cmntlen,self.disk,inat,extat,
       self.localoffset)=struct.unpack("<HHHHHHIIIHHHHHII", data)
      self.postinit(fd)
      fd.seek(self.fldlen, 1)      

class localHeader(fileHeader):
   
   def __init__(self, fd):
      super(localHeader, self).__init__()
      self.is_local = True
      data=r.read(26)
      if data is None or len(data) != 26:
         raise IOError, "file truncated or bad offset (local entry)"
      (self.version, self.flags, self.method, self.time,
       self.date, self.crc, self.csize, self.size, self.namelen,
       self.fldlen)=struct.unpack("<HHHHHIIIHH", data)
      self.postinit(fd)
      fd.seek(self.fldlen, 1)

class zipState(object):
   def __init__(self, fd):
      self.fd = fd
      
   def read_magic(self):
      data=self.fd.read(4)
      if data is None or len(data) == 0:
         raise IOError, "file truncated or bad offset (magic)"
      (hdr1,hdr2,hdr3)=struct.unpack("<2sbb", data)
      if hdr1 != "PK" and hdr1 != "AB":
         print hdr1, hdr2, hdr3
         raise ValueError, "bad magic (file format error or misaligned)"
      if hdr2 < 0 or hdr2 >= 10 or hdr3 < 0 or hdr3 >= 10:
         raise ValueError, "bad magic (zip header id not small integers)"
      return "{0}{1}".format(hdr2,hdr3)

   def validate_or_skip_data(self, hdr):
      if hdr.method == 8 and hdr.safe_flags:
         (acrc, cbytes, dbytes)=decompress_data(self.fd, hdr.csize)
         if hdr.size > 0 and acrc is None:
            print "CRC mismatch: Actual {0}, expected {1}".format(None, hdr.crc)
         elif acrc is None:
            pass
         elif acrc & 0xffffffff != hdr.crc:
            print "CRC mismatch: Actual {0}, expected {1}".format(acrc & 0xffffffff, hdr.crc)
         else:
            hdr.tested = True
         if cbytes != hdr.csize:
            print "Compressed size mismatch: Actual {0}, expected {1}".format(cbytes, hdr.csize)
         if dbytes != hdr.size:
            print "File size mismatch: Actual {0}, expected {1}".format(dbytes, hdr.size)
      else:
         self.fd.seek(hdr.csize, 1)

      
   def read_one_pair(self):
      offset = self.fd.tell()
      fmt=self.read_magic()
      cds = None
      seekback = None
      if fmt != "12":
         if fmt == "56":
            return False
         raise ValueError, "Unexpected zip header PK{0}, expecting PK12 (CDS)".format(fmt)
      cds = cdsHeader(self.fd)
      cds.validate_features()
      if cds.disk == self.thisdisk:
         seekback=self.fd.tell()
         self.fd.seek(cds.localoffset)
         fmt=self.read_magic()
         if fmt != "34":
            raise ValueError, "Unexpected zip header PK{0}, expecting PK34 (local)".format(fmt)
         lh = localHeader(self.fd)

         compare_headers(cds, lh)
         self.validate_or_skip_data(cds)
         self.fd.seek(seekback)
      self.current = cds
      return True

with file(sys.argv[1], "rb") as r:
   zs = zipState(r)
   ret=scan_cds(r)
   curofs=r.tell()
   fmt = zs.read_magic()
   if fmt != "56":
      raise ValueError, "End of CDS missing"
   data=r.read(18)
   (thisdsk,dsk,tent,allent,dirsz,cdsofs,cmntsz)=struct.unpack("<HHHHIIH",data)
   print "End of CDS found at {}".format(curofs)
   zs.thisdisk = thisdsk

   cmnt=r.read(cmntsz)
   if (dsk == thisdsk):
      r.seek(cdsofs, 0)
      while zs.read_one_pair():
         print "{0}->{1} bytes of {2}{3}".format(zs.current.csize, zs.current.size, zs.current.filename, " [OK]" if zs.current.tested else "")
   else:
      print "The Central directory does not begin on this disk"

    
