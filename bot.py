'''based on volf ram code'''
'''This owful piece of code is able to login to tibia server, using protocol version 1098'''
import random
import struct
import zlib
import socket
OT_RSA = 109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413
def rsa_encrypt(m):
  m = sum(x*pow(256, i) for i, x in enumerate(reversed(m)))
  c = pow(m, 65537, OT_RSA)
  return bytes((c >> i) & 255 for i in reversed(range(0, 1024, 8)))
def rsa_encrypt(m):
  m = sum(x*pow(256, i) for i, x in enumerate(reversed(m)))
  c = pow(m, 65537, OT_RSA)
  return bytes((c >> i) & 255 for i in reversed(range(0, 1024, 8)))

def xtea_decrypt_block(block, key):
  v0, v1 = struct.unpack('=2I', block)
  k = struct.unpack('=4I', key)
  delta, mask, rounds = 0x9E3779B9, 0xFFFFFFFF, 32
  sum = (delta * rounds) & mask
  for round in range(rounds):
      v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
      sum = (sum - delta) & mask
      v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
  return struct.pack('=2I', v0, v1)
def xtea_decrypt(data, key):
  return b''.join(xtea_decrypt_block(data[i:i + 8], key) for i in range(0, len(data), 8))
def make_login_request(xtea_key, acc_name, acc_password):
  login_request = struct.pack('=B16sH%isH%is' % (len(acc_name), len(acc_password)), 0, xtea_key, len(acc_name), acc_name, len(acc_password), acc_password)
  login_request += bytes(random.randint(0, 255) for i in range(len(login_request), 128))
  login_request = struct.pack('=BHHIIIIB', 1, 2, 1098, 1098, 0x4E12DAFF, 0x4E12DB27, 0x4E119CBF, 0) + rsa_encrypt(login_request)
  login_request = struct.pack('=HI', len(login_request) + 4, zlib.adler32(login_request)) + login_request
  return login_request
def make_entergame_request(session_key, charname, timestamp, randomNumber):
    print('sessionkey', session_key, charname)
    '''
    It's a bit outdated, but still helpful.
    Recent specification can be found here: 
    https://github.com/edubart/otclient and here
    https://github.com/otland/forgottenserver
    10						8			packet ID
	1 or 2					16			operating system: linux 1, windows 2
	854						16			version without dot
	RSA						128*8		RSA encrypted block
	{
		0					8			it must be 0
		(random)				128			XTEA key
		0 or 1				8			GM flag: normal character 0, GM 1
		length of accname		16
		"accname"			length*8		account name; string in ASCII without null byte
		length of character	16
		"character"			length*8		character name; string in ASCII without null byte
		length of pass		16
		"pass"				length*8		password; string in ASCII without null byte
		(security bytes)		5*8			security bytes received from server
		(any(?))				?			padding; RSA is a block cipher - it must encrypt 128 bytes or 256 bytes etc.
	}'''
    #RSA encrypted part
    entergame_request = struct.pack('=B16sBH%isH%isIB' % (len(session_key), len(charname)), 0, xtea_key, 0, len(session_key), session_key, len(charname), charname, timestamp, randomNumber)
    entergame_request += bytes(random.randint(0,255) for i in range(len(entergame_request), 128))
    entergame_request = struct.pack('=BHHIHB', 10, 2, 1098, 1098, 65, 0) + rsa_encrypt(entergame_request)
    entergame_request = struct.pack('=HI', len(entergame_request)+4, zlib.adler32(entergame_request)) + entergame_request

    return entergame_request
def get_string(packet_bytes):
    return bytes(next(packet_bytes) for i in range(next(packet_bytes) + 256*next(packet_bytes)))
def get_int(packet_bytes, bits):
    return sum(next(packet_bytes)*pow(256, i) for i in range(bits//8))
def recv_packets(s):
    #decode xtea
    packet = xtea_decrypt(s.recv(4 + struct.unpack('=H', s.recv(2))[0])[4:], xtea_key)
    packet_bytes = iter(packet[2:2 + struct.unpack('=H', packet[:2])[0]])
    for packet_code in packet_bytes:
        if packet_code == 11:#LoginServerErrorNew
            error = get_string(packet_bytes)
            yield 'LoginServerErrorNew', error
        elif packet_code == 20:#LoginServerMotd
            motd = get_string(packet_bytes)
            yield 'LoginServerMotd', motd
        elif packet_code == 30: #LoginServerUpdateNeeded
            yield 'LoginServerUpdateNeeded', 'Clients need update'
        elif packet_code == 12: #LoginServerTokenSuccess
            print('unknown: ', get_int(packet_bytes, 8))
            yield 'LoginServerTokenSuccess', None
        elif packet_code == 100: #Character list
            worlds = {}
            worldsCount = get_int(packet_bytes, 8)
            for world in range(worldsCount):
                worldId = get_int(packet_bytes, 8)
                worlds[worldId] = {}
                worlds[worldId]['name'] = get_string(packet_bytes)
                worlds[worldId]['ip'] = get_string(packet_bytes)
                worlds[worldId]['port'] = get_int(packet_bytes, 16)
                worlds[worldId]['previewState'] = get_int(packet_bytes, 8)
            charactersCount = get_int(packet_bytes, 8)
            characters = {}
            for character in range(charactersCount):
                worldId = get_int(packet_bytes, 8)
                characters[character] = {}
                characters[character]['name'] = get_string(packet_bytes)
                characters[character]['worldName'] = worlds[worldId]['name']
                characters[character]['worldIp'] = worlds[worldId]['ip']
                characters[character]['port'] = worlds[worldId]['port']
                characters[character]['previewState'] = worlds[worldId]['previewState']
            account = {}
            account['premDays'] = get_int(packet_bytes, 16)
            yield 'Characters list', characters
        elif packet_code == 101: #character list extened
            yield 'Character list extened', None
        elif packet_code == 40: #Session key
            session_key = get_string(packet_bytes)
            yield 'Session key', session_key
        else:
            yield ('unknown packet code %d (0x%x)' % (packet_code, packet_code), None)
def recv_game_packets(s):
    packet = s.recv(4 + struct.unpack('=H', s.recv(2))[0])[4:]
    packet_bytes = iter(packet[2:2 + struct.unpack('=H', packet[:2])[0]])
    for packet_code in packet_bytes:
        if packet_code == 31: #GameServerChallenge
            timestamp = get_int(packet_bytes, 32)
            randomNumber = get_int(packet_bytes, 8)
            print(timestamp, randomNumber)
            yield 'GameServerChallenge', [timestamp, randomNumber]
        else:
            yield ('unknown packet code %d (0x%x)' % (packet_code, packet_code), None)
xtea_key = bytes(random.randint(0,255) for i in range(16))
print('xtea_key', xtea_key)
acc_name = b'bot1xd'
acc_password = b'dupa123'
session_key = ''
with socket.socket() as s:
    s.connect(('144.217.149.144', 7171))
    s.sendall(make_login_request(xtea_key, acc_name, acc_password))
    for packet_name, packet_data in recv_packets(s):
        print(packet_name, packet_data)
        if(packet_name == 'Characters list'):
            chars = packet_data
            print(chars)                        
        if packet_name == 'Session key':
            session_key = packet_data
    with socket.socket() as c:
        c.connect((chars[0]['worldIp'], chars[0]['port']))
        for packet_name, packet_data in recv_game_packets(c):
            print(packet_name, packet_data)
            if(packet_name == 'GameServerChallenge'):
                print('sending enteragame packet')
                c.sendall(make_entergame_request(session_key, chars[0]['name'], packet_data[0], packet_data[1]))