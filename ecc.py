from __future__ import print_function
from Crypto.PublicKey import ECC
from ecies.utils import generate_eth_key, generate_key
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

def println(text):
    print(text,end='\n\n')

def point_to_public_key_bytes(point):
        return bytes([4]) + long_to_bytes(point.x) + long_to_bytes(point.y)

def point_to_secret_key_bytes(point):
        return long_to_bytes(point)

def createCTypeArrayfromKeyPair(keyPair):
    key_str = "{0x"
    for i in range(len(keyPair)):
        key_str += keyPair[i]
        if i % 2 != 0 and i != len(keyPair) - 1:
            key_str += ", 0x"
    key_str += '}'
    return key_str

class NISTP_Pair_Ops:

    key = None

    @staticmethod
    def generate_key(file,curve='P-256'):
        NISTP_Pair_Ops.key = (ECC.generate(curve=curve))
        NISTP_Pair_Ops.save_key(file)
    @staticmethod
    def save_key(filename='myprivatekey.pem'):
        f = open(filename,'wt')
        f.write(NISTP_Pair_Ops.key.export_key(format='PEM'))
        f.close()
    @staticmethod
    def read_key():
        f = open('myprivatekey.pem','rt')
        NISTP_Pair_Ops.key = ECC.import_key(f.read())
        f.close()
        return NISTP_Pair_Ops.key

println("")

NISTP_Pair_Ops.generate_key('spareprivatekey.pem')
nist_p_pair = NISTP_Pair_Ops.read_key()
pub_key = nist_p_pair.pointQ
sec_key = nist_p_pair.d
println(createCTypeArrayfromKeyPair(nist_p_pair.export_key(format='DER').hex()))
println(createCTypeArrayfromKeyPair(point_to_secret_key_bytes(sec_key).hex()))
println(createCTypeArrayfromKeyPair(point_to_public_key_bytes(pub_key).hex()))

h = SHA256.new()
digest = b'Hello'
h.update(digest)
signer = DSS.new(nist_p_pair, 'fips-186-3',encoding='der')
signature = signer.sign(h)
println(createCTypeArrayfromKeyPair(signature.hex()))
