import random
import socket
import struct
import zlib

OT_RSA = 109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413
headerSize = 6
class TibiaPacket(object):
    def __init__(self, packetBytes=bytearray()):
        self.packet = bytearray(packetBytes)
        self.position = 0
        self.encryptionPos = 0
    def handleIncoming(self, s):
        print(s.recv(1024))
    '''header'''
    def writeHeader(self):
        self.packet = struct.pack('=HI', len(self.packet) + 4, zlib.adler32(self.packet)) + self.packet
    def readHeader(self):
        self.packetSize = self.getU16()
        self.adler32Checksum = self.getU32()
        return {'packetSize': self.packetSize, 'checksum': self.adler32Checksum}
    '''XTEA stuff'''
    def xtea_decrypt_block(self, block):
        v0, v1 = struct.unpack('=2I', block)
        k = struct.unpack('=4I', xtea_key)
        delta, mask, rounds = 0x9E3779B9, 0xFFFFFFFF, 32
        sum = (delta * rounds) & mask
        for round in range(rounds):
            v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
            sum = (sum - delta) & mask
            v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
        return struct.pack('=2I', v0, v1)
    def xtea_decrypt(self):
        self.packet[headerSize:] = b''.join(self.xtea_decrypt_block(self.packet[headerSize:][i:i + 8]) for i in range(0, len(self.packet) - headerSize, 8))
        self.packet[headerSize:] = self.packet[headerSize:][2:2+self.packetSize]
    '''RSA stuff'''
    def setEncryptionPos(self):
        self.encryptionPos = len(self.packet)
    def rsa_encrypt(self):
        m = sum(x*pow(256, i) for i, x in enumerate(reversed(self.packet[self.encryptionPos:])))
        c = pow(m, 65537, OT_RSA)
        self.packet[self.encryptionPos:] = bytearray((c >> i) & 255 for i in reversed(range(0, 1024, 8)))
        self.encryptionPos = 0
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
def makeLoginPacket(xtea_key, acc_name, acc_password):
    packet = TibiaPacket() #get charlist packet (login)
    packet.writeU8(1)
    packet.writeU16(2)
    packet.writeU16(1100)
    packet.writeU32(1100)
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
    return packet.getPacket()
def loginPacketHandler(s):
    packetBytes = s.recv(headerSize)
    packetSize, adler32Checksum = struct.unpack('=HI', packetBytes)
    packetBytes += s.recv(packetSize - 2) # U16 size
    received_packet = TibiaPacket(packetBytes)
    print(received_packet.readHeader())
    received_packet.xtea_decrypt()
    print(received_packet.getPacket())
    # for index in range(len(received_packet.getPacket()[headerSize:])):
    while received_packet.position < len(received_packet.getPacket()[headerSize:]):
        packetCode = received_packet.getU8()
        if packetCode == 10: #servererror
            yield 'servererror', received_packet.getString()
        elif packetCode == 11: #loginerror
            yield 'loginerror', received_packet.getString()
        elif packetCode == 20: #loginservermotd
            yield 'loginservermotd', received_packet.getString()
        elif packetCode == 40: #session key
            yield 'sessionkey', received_packet.getString()
        elif packetCode == 100: #charlist
            worlds = {}
            worldsCount = received_packet.getU8()
            print('worldsCount', worldsCount)
            for world in range(worldsCount):
                worldId = received_packet.getU8()
                worlds[world] = {}
                worlds[worldId]['name'] = received_packet.getString()
                worlds[worldId]['ip'] = received_packet.getString()
                worlds[worldId]['port'] = received_packet.getU16()
                worlds[worldId]['previewState'] = received_packet.getU8()
            print(worlds)
            charactersCount = received_packet.getU8()
            characters = {}
            for character in range(charactersCount):
                worldId = received_packet.getU8()
                characters[character] = {}
                characters[character]['name'] = received_packet.getString()
                characters[character]['worldName'] = worlds[worldId]['name']
                characters[character]['worldIp'] = worlds[worldId]['ip']
                characters[character]['worldPort'] = worlds[worldId]['port']
                characters[character]['previewState'] = worlds[worldId]['previewState']
            print(characters)
            print('premdays: ', received_packet.getU32() + received_packet.getU32())
        else:
            yield '%i unknown packport code %d (0x%x)' % (index, packetCode, packetCode), None 
acc_name = b'bot1xd'
acc_password = b'dupa123'

xtea_key = bytes(random.randint(0,255) for i in range(16))
# print('xtea_key', xtea_key)
with socket.socket() as s:
    s.connect(('144.217.149.144', 7171))
    s.sendall(makeLoginPacket(xtea_key, acc_name, acc_password))
    for data,data2 in loginPacketHandler(s):
        print(data, data2)
