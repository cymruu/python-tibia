import random
import struct
import zlib

OT_RSA = 109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413

class TibiaPacket(object):
    def __init__(self):
        self.packet = bytearray()
        self.position = 0
    def writeHeader(self):
        self.packet = struct.pack('=HI', len(self.packet) + 4, zlib.adler32(self.packet)) + self.packet
    '''writters'''
    def writeU8(self, n):
        self.packet+=struct.pack('=B', n)
    def writeU16(self, n):
        self.packet+=struct.pack('=H', n)
    def writeU32(self, n):
        self.packet+=struct.pack('=I', n)
    def writeString(self, s):
        stringLength = len(s)
        self.writeU16(len(stringLength))
        self.packet += struct.pack('%is' % (len(stringLength)))
    '''readers'''
    def getU8(self):
        n = self.packet[self.position]
        self.position+=1
        return n
    def getU16(self):
        n = struct.unpack('=H', self.packet[self.position:self.position+2])[0]
        self.position+=2
        return n
    def getU32(self):
        n = struct.unpack('=I', self.packet[self.position:self.position+4])[0]
        self.position+=4
        return n
    def getString(self):
        raise NotImplementedError
    def getDouble(self, parameter_list):
        raise NotImplementedError
    def printPacket(self):
        print(self.packet)

packet = TibiaPacket()
packet.writeU8(1)
packet.writeU16(2)
packet.writeU16(1098)
packet.writeU32(1098)
packet.writeU32(0x4E12DAFF)
packet.writeU32(0x4E12DB27)
packet.writeU32(0x4E119CBF)
packet.writeU8(0)
packet.printPacket()
print(packet.getU8())
print(packet.getU16())
print(packet.getU16())
print(packet.getU32())
print(packet.getU32())
print(packet.getU32())
print(packet.getU32())
print(packet.getU8())