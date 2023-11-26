import hmac
import hashlib
#import tensorflow as tf
#import tf_encrypted as tfe
import time
import sys
import struct
import random
import psutil
import pymongo

#using model unit32 and unit8


"""HyperParameters :)"""
timestep = 30
T0 = 0

client = pymongo.MongoClient("mongodb+srv://testuser750:mongoDb_750@ehrblock.nvomfgg.mongodb.net/?retryWrites=true&w=majority")
db = client.testuser750
mydb=client["newDB"]


mycol=mydb["Blockhead"]

mylist=mycol.find_one()
#mylist=mycol.find_one({}, sort=[("position", pymongo.DESCENDING)])
cursor = mycol.find().sort([('timestamp', -1)]).limit(1)
#cursor=mycol.find()
print("================")
for each_mylist in cursor:
    print(each_mylist)

def HOTP(K, C, digits=10):
    """HTOP:
    K is the shared key
    C is the counter value
    digits control the response length
    """
    K_bytes = K.encode()
    C_bytes = struct.pack(">Q", C)
    hmac_sha512 = hmac.new(key = K_bytes, msg=C_bytes, digestmod=hashlib.sha512).hexdigest()
    return Truncate(hmac_sha512)[-digits:]

def Truncate(hmac_sha512):
    """truncate sha512 value"""
    offset = int(hmac_sha512[-1], 16)
    binary = int(hmac_sha512[(offset *2):((offset*2)+8)], 16) & 0x7FFFFFFF
    return str(binary)

def TOTP(K, digits=10, timeref = 0, timestep = 30):
    """TOTP, time-based variant of HOTP
     digits control the response length
    the C in HOTP is replaced by ( (currentTime - timeref) / timestep )
     """
    C = int ( time.time() - timeref ) // timestep
    
    return HOTP(K, C, digits = digits)

message_str = list(str(each_mylist))
def token_generate():
    print('10 digit token generation using hashing blockcahin technique ')
    start_time=time.time()
    passwd = TOTP(str(random.randint(500,1000)), random.randint(30,40), T0, timestep).zfill(10)
    end_time=time.time()
    return (passwd)

