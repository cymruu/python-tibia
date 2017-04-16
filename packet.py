import random
import socket
import struct
import zlib

OT_RSA = 109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413
headerSize = 6
class TibiaPacket(object):
    def __init__(self, packetBytes=bytearray()):
        self.header = packetBytes[:headerSize]
        self.packet = packetBytes[headerSize:]
        self.position = 0
        self.encryptionPos = 0
    '''header'''
    def writeHeader(self):
        self.header = struct.pack('=HI', len(self.packet) + 4, zlib.adler32(self.packet)) + self.packet
    def readHeader(self):
        packetSize, adler32Checksum = struct.unpack('=HI', self.header)
        self.packetSize = packetSize
        self.adler32 = adler32Checksum
        return {'packetSize': packetSize, 'adler32Checksum': adler32Checksum}
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
        self.packet = b''.join(self.xtea_decrypt_block(self.packet[i:i + 8]) for i in range(0, len(self.packet), 8))
    def trim_size(self):
        self.packet = self.packet[2:2+self.packetSize]
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
    def getWholePacket(self):
        return self.header + self.packet
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
    return packet.getWholePacket()
def makeEnterGamePacket(sessionkey, charname, timestamp, randomNumber):
    packet = TibiaPacket()
    packet.writeU8(10)
    packet.writeU16(2)
    packet.writeU16(1098)
    packet.writeU32(1098)
    packet.writeU16(65)
    packet.writeU8(0)
    packet.setEncryptionPos()
    packet.writeU8(0)
    packet.writeBytes(xtea_key)
    packet.writeU8(0)
    packet.writeString(sessionkey)
    packet.writeString(charname)
    packet.writeU32(timestamp)
    packet.writeU8(randomNumber)
    packet.fillBytes()
    packet.rsa_encrypt()
    packet.writeHeader()
    return packet.getWholePacket()
def loginPacketHandler(s):
    packetBytes = s.recv(headerSize)
    packetSize, adler32Checksum = struct.unpack('=HI', packetBytes)
    packetBytes += s.recv(packetSize - 2) # U16 size
    received_packet = TibiaPacket(packetBytes)
    received_packet.readHeader()
    received_packet.xtea_decrypt()
    received_packet.trim_size()
    # for index in range(len(received_packet.getPacket())):
    index =0 
    while received_packet.position < len(received_packet.getPacket()):
        packetCode = received_packet.getU8()
        if packetCode == 10: #servererror
            yield 'servererror', received_packet.getString()
        elif packetCode == 11: #loginerror
            yield 'loginerror', received_packet.getString()
        elif packetCode == 20: #loginservermotd
            yield 'loginservermotd', received_packet.getString()
        elif packetCode == 40: #session key
            global sessionkey
            sessionkey = received_packet.getString()
            yield 'sessionkey', sessionkey
        elif packetCode == 100: #charlist
            worlds = {}
            worldsCount = received_packet.getU8()
            for world in range(worldsCount):
                worldId = received_packet.getU8()
                worlds[world] = {}
                worlds[worldId]['name'] = received_packet.getString()
                worlds[worldId]['ip'] = received_packet.getString()
                worlds[worldId]['port'] = received_packet.getU16()
                worlds[worldId]['previewState'] = received_packet.getU8()
            charactersCount = received_packet.getU8()
            global characters
            for character in range(charactersCount):
                worldId = received_packet.getU8()
                characters[character] = {}
                characters[character]['name'] = received_packet.getString()
                characters[character]['worldName'] = worlds[worldId]['name']
                characters[character]['worldIp'] = worlds[worldId]['ip']
                characters[character]['worldPort'] = worlds[worldId]['port']
                characters[character]['previewState'] = worlds[worldId]['previewState']
            print('premdays: ', received_packet.getU32() + received_packet.getU32())
            yield 'characters', characters
        else:
            yield 'unknown packet', '%i  %d (0x%x)' % (index, packetCode, packetCode)
def handleGamePackets(c):
    while True:
        packetBytes = c.recv(headerSize)
        packetSize, adler32Checksum = struct.unpack('=HI', packetBytes)
        packetBytes += c.recv(packetSize - 2) # U16 size
        received_packet = TibiaPacket(packetBytes)
        received_packet.readHeader()
        received_packet.trim_size()
        while received_packet.position < len(received_packet.getPacket()):
            packetCode = received_packet.getU8()
            if packetCode == 31: #server challenge
                timestamp = received_packet.getU32()
                randomNumber = received_packet.getU8()
                c.sendall(makeEnterGamePacket(sessionkey, characters[0]['name'], timestamp, randomNumber))
                yield 'serverchallenge', {'timestamp': timestamp, 'randomNumber': randomNumber}
            elif packetCode == 15: #gameinitstatus
                playerId = received_packet.getU32()
                serverBeat = received_packet.getU16()
                yield 'entergame', {'id': playerId, 'serverBeat': serverBeat}
            else:
                received_packet.position+=received_packet.packetSize-1#TODO: adjust it
                yield 'unknown packet', '%i  %d (0x%x)' % (0, packetCode, packetCode)
acc_name = b'bot1xd'
acc_password = b'dupa123'

characters = {}
sessionkey = None
xtea_key = bytes(random.randint(0,255) for i in range(16))
with socket.socket() as c:
    c.connect(('144.217.149.144', 7171))
    c.sendall(makeLoginPacket(xtea_key, acc_name, acc_password))
    for packet, data in loginPacketHandler(c):
        print(packet, data)
# we have everything, lets login
with socket.socket() as c:# client
    c.connect((characters[0]['worldIp'], characters[0]['worldPort']))
    i = 0
    for packet, data in handleGamePackets(c):
        print(packet, data)
        i+=1
        if(i>100):break