import random
import struct
import zlib
import socket

OT_RSA = 109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413

class TibiaPacket(object):
    def __init__(self):
        self.packet = bytearray()
        self.position = 0
        self.encryptionPos = 0
    '''header'''
    def writeHeader(self):
        self.packet = struct.pack('=HI', len(self.packet) + 4, zlib.adler32(self.packet)) + self.packet
    '''RSA stuff'''
    def setEncryptionPos(self):
        self.encryptionPos = len(self.packet)
    def rsa_encrypt(self):
        m = sum(x*pow(256, i) for i, x in enumerate(reversed(self.packet[self.encryptionPos:])))
        c = pow(m, 65537, OT_RSA)
        self.packet[self.encryptionPos:] = bytearray((c >> i) & 255 for i in reversed(range(0, 1024, 8)))
    def fillBytes(self):
        self.packet += bytearray(random.randint(0,255) for i in range(len(self.packet)-self.encryptionPos, 128))
    '''writters'''
    def writeU8(self, n):
        self.packet+=struct.pack('=B', n)
    def writeU16(self, n):
        self.packet+=struct.pack('=H', n)
    def writeU32(self, n):
        self.packet+=struct.pack('=I', n)
    def writeString(self, s):
        if type(s) is str:
            s = bytes(str)
        stringLength = len(s)
        self.writeU16(stringLength)
        self.packet += struct.pack('%is' % (stringLength), s)
    def writeBytes(self, b):
        self.packet+=b
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
        stringLength = self.getU16()
        string = struct.unpack('=%is' % (stringLength), self.packet[self.position:self.position+stringLength])[0]
        self.position+=stringLength
        return string
    def getDouble(self, parameter_list):
        raise NotImplementedError
    def getPacket(self):
        return self.packet

acc_name = b'bot1xd'
acc_password = b'dupa123'

xtea_key = bytes(random.randint(0,255) for i in range(16))
print('xtea_key', xtea_key)

packet = TibiaPacket() #get charlist packet (login)
packet.writeU8(1)
packet.writeU16(2)
packet.writeU16(1098)
packet.writeU32(1098)
packet.writeU32(0x4E12DAFF)
packet.writeU32(0x4E12DB27)
packet.writeU32(0x4E119CBF)
packet.writeU8(0)
packet.setEncryptionPos()
packet.writeU8(0) #0 first RSA byte must be 0
packet.writeBytes(xtea_key) #we're writing XTEA key, ist just a set of bytes so we i have to use dedicated function
packet.writeString(acc_name)
packet.writeString(acc_password)
packet.fillBytes()
packet.rsa_encrypt()
packet.writeHeader()
with socket.socket() as s:
    s.connect(('144.217.149.144', 7171))
    s.sendall(packet.getPacket())
    print(s.recv(1024))