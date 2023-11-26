from flask import Flask,render_template,request,url_for,session,redirect,jsonify
import json,sqlite3
import pymongo
from hashlib import sha256
import tensorflow as tf
import tfe_encrypted as tfe
import numpy as np
from datetime import date
import datetime
import json



client = pymongo.MongoClient("mongodb+srv://testuser750:mongoDb_750@ehrblock.nvomfgg.mongodb.net/?retryWrites=true&w=majority")
db = client.testuser750
mydb=client["newDB"]


mycol=mydb["Blockhead"]
mylist=mycol.find_one()

cursor = mycol.find().sort([('timestamp', -1)]).limit(1)

#cursor=mycol.find()

print("================")
for each_mylist in cursor:
    print(each_mylist)


def int_list_to_hex(l):
    return ''.join("{0:0{1}x}".format(x, 2) for x in l)

def int_list_to_string(l):
    return ''.join(chr(x) for x in l)

import tensorflow.compat.v1 as tf  #using model unit32 and unit8 
tf.disable_v2_behavior()

message_str = list(str(each_mylist))
message = tf.constant([ord(c) for c in message_str], tf.uint8)
key_uint32 = tf.Variable(tf.random.uniform(message.shape, minval=0, maxval=2**8, dtype=tf.int32))
key = tf.cast(key_uint32, tf.uint8)
encrypt_xor = tf.bitwise.bitwise_xor(message, key)
decrypt_xor = tf.bitwise.bitwise_xor(encrypt_xor, key)
with tf.compat.v1.Session().as_default() as session:
    session.run(tf.global_variables_initializer())
    print('key:'.ljust(24), int_list_to_hex(key.eval()))
    print('message:'.ljust(24), int_list_to_string(message.eval()))
    ciphertext = encrypt_xor.eval()
    print('encrypted ciphertext:'.ljust(24), int_list_to_hex(ciphertext))

    plaintext = decrypt_xor.eval()
    print('decrypted plaintext:'.ljust(24), int_list_to_string(plaintext))


encrypted=mylist
decrypted=mylist
if encrypted==decrypted:
    print('DATA is valid')
else:
    print('DATA is not valid')