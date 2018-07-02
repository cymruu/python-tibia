import random
import socket
import zlib
import struct
import math
import binascii
OT_RSA = 109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413
def rsa_encrypt(m):
  m = sum(x*pow(256, i) for i, x in enumerate(reversed(m)))
  c = pow(m, 65537, OT_RSA)
  return bytes((c >> i) & 255 for i in reversed(range(0, 1024, 8)))
def xtea_decrypt_block(block, key):
  v0, v1 = struct.unpack('=2I', block)
  k = struct.unpack('=4I', key)
  delta, mask, rounds = 0x9E3779B9, 0xFFFFFFFF, 32
  sum = (delta * rounds) & mask
  for _ in range(rounds):
      v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
      sum = (sum - delta) & mask
      v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
  return struct.pack('=2I', v0, v1)
def xtea_decrypt(data, key):
  return b''.join(xtea_decrypt_block(data[i:i + 8], key) for i in range(0, len(data), 8))

class Packet():
    def __init__(self):
        self.size = 0
        self.header = bytearray()
        self.data = bytearray()
    def readHeader(self):
        return struct.unpack("=HI", self.header)
    def writeByte(self, d: int):
        self.data += bytes([d])
        self.size += 1

    def writeUInt16(self, d: int):
        self.data += struct.pack("=H", d)
        self.size += 2

    def writeUInt32(self, d: int):
        self.data += struct.pack("=I", d)
        self.size += 4

    def writeBytes(self, d):
        self.data += d
        self.size += len(d)

    def writeString(self, d):
        self.writeUInt16(len(d))
        self.data += struct.pack(("=%is" % len(d)), d)

    def makeHeader(self):
        self.header = struct.pack("=HI", len(self.data) + 4, zlib.adler32(self.data))

    def bytes(self):
        self.makeHeader()
        return bytes(self.header+self.data)
    def parse(self):
        def readString(packet_bytes):
            return bytes(next(packet_bytes) for i in range(next(packet_bytes) + 256*next(packet_bytes)))
        def readInt(packet_bytes, bits):
            return sum(next(packet_bytes)*pow(256, i) for i in range(bits//8))
        def parseCharacterList(packet_bytes):
            worlds = {}
            worldsCount = readInt(packet_bytes, 8)
            for _ in range(worldsCount):
                world = {}
                world["id"] = readInt(packet_bytes, 8)
                world["name"] = readString(packet_bytes)
                world["ip"] = readString(packet_bytes)
                world["port"] = readInt(packet_bytes, 16)
                world["previewState"] = readInt(packet_bytes, 8)
                worlds[world["id"]] = world
            characters = {}
            charactersCount = readInt(packet_bytes, 8)
            for i in range(charactersCount):
                character = {}
                worldId = readInt(packet_bytes, 8)
                character["name"] = readString(packet_bytes)
                character["worldName"] = worlds[worldId]["name"]
                character["worldIp"] = worlds[worldId]["ip"]
                character["worldPort"] = worlds[worldId]["port"]
                character["previewState"] = worlds[worldId]["previewState"]
                characters[i] = character
            return characters
        packet_bytes = iter(self.data)
        for packet_code in packet_bytes:
            if packet_code == 10:
                yield "LoginServerError", {"packet_code":packet_code, "message":readString(packet_bytes)}
            elif packet_code == 20:
                yield "Motd", {"packet_code": packet_code, "message": readString(packet_bytes)}
            elif packet_code == 100:
                yield "PacketCharacterList", {"packet_code": packet_code, "chars":parseCharacterList(packet_bytes)}
            else:
                yield {"error":"unkown packet_code", "packet_code": packet_code}
            # yield list(zip([x for x in self.data], [chr(x) for x in self.data]))

class LoginRequest(Packet):
    def __init__(self, xtea_key, acc_name, acc_password):
        super(LoginRequest, self).__init__()
        self.writeByte(1)
        self.writeUInt16(2)
        self.writeUInt16(1100)
        self.writeUInt32(1100)
        self.writeUInt32(0x4E12DAFF)
        self.writeUInt32(0x4E12DB27)
        self.writeUInt32(0x4E119CBF)
        self.writeByte(0)
        offset = len(self.data)
        self.writeByte(0) #0 first RSA byte must be 0
        self.writeBytes(xtea_key) #we're writing XTEA key, ist just a set of bytes so we i have to use dedicated function
        self.writeString(acc_name)
        self.writeString(acc_password)
        self.writeBytes((bytes(0 for i in range(len(self.data)-offset, 128)))) #fill with zeros
        self.data[offset:] = rsa_encrypt(self.data[offset:])
        self.writeString(bytes(''.join([chr(122) for x in range(len(self.data), 351)]), 'ascii')) #fake GPU details
class Tibia():
    def __init__(self, RSAKEY: int, IP: str, loginPort: int, gamePort: int, login: str, password: str):
        self.RSA_KEY = RSAKEY
        # self.XTEA = bytes(random.randint(0, 255) for i in range(16))
        self.XTEA = bytes(122 for i in range(16))
        self.acc_login = bytes(login, 'ascii')
        self.acc_password = bytes(password, 'ascii')
        self.IP = IP
        self.loginPort = loginPort
        self.gamePort = gamePort
    def readFromLogin(self, s):
            packet = Packet()
            packet.header = s.recv(6)
            packet_length, adler32 = packet.readHeader()
            print("Received packet length: {} with sum: {}".format(packet_length, adler32))
            remaining_data = packet_length - 4 #adler32 size
            packet.data = s.recv(remaining_data)
            packet.data = xtea_decrypt(packet.data, self.XTEA)
            print(packet.data)
            for parsed_packet in packet.parse():
                yield parsed_packet
    def login(self):
        with socket.socket() as loginServer:
            print((self.IP, self.loginPort))
            loginServer.connect((self.IP, self.loginPort))
            print("connected")
            loginPacket = LoginRequest(self.XTEA, self.acc_login, self.acc_password)
            data = loginPacket.bytes()
            print(data, len(data))
            loginServer.sendall(data)
            for packet in self.readFromLogin(loginServer):
                print(packet)


tibia = Tibia(OT_RSA, "hexera.net", 7171, 7172, "nimbus2000", "dupa123")
tibia.login()
