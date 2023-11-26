from flask import Flask, render_template, request, url_for, session, redirect, jsonify
import json
import sqlite3
from datetime import date
import datetime
from time import time
from hashlib import sha256
import datetime
import time
import pymongo
from passlib.context import CryptContext
import requests
import ipfshttpclient
import os
import webbrowser
from werkzeug.utils import secure_filename

import hmac
import hashlib
import sys
import struct
import random


from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from blockchain.create import create_transaction, get_transactions, get_transaction_by_record_id

# tf.compat.v1.disable_eager_execution()

"""HyperParameters :)"""
timestep = 30
T0 = 0

# def int_list_to_hex(l):
#     return ''.join("{0:0{1}x}".format(x, 2) for x in l)

# def int_list_to_string(l):
#     return ''.join(chr(x) for x in l)

# import tensorflow.compat.v1 as tf  #using model unit32 and unit8
# tf.disable_v2_behavior()

# my_list="patient registration succesfull"
# message_str = (my_list)
# message = tf.constant([ord(c) for c in message_str], tf.uint8)

# key_uint32 = tf.Variable(tf.random.uniform(message.shape, minval=0, maxval=2**8, dtype=tf.int32))
# key = tf.cast(key_uint32, tf.uint8)

# encrypt_xor = tf.bitwise.bitwise_xor(message, key)
# decrypt_xor = tf.bitwise.bitwise_xor(encrypt_xor, key)

# with tf.compat.v1.Session().as_default() as session:
#     session.run(tf.global_variables_initializer())
#     print('key:'.ljust(24), int_list_to_hex(key.eval()))
#     print('message:'.ljust(24), int_list_to_string(message.eval()))

#     ciphertext = encrypt_xor.eval()
#     print('encrypted ciphertext:'.ljust(24), int_list_to_hex(ciphertext))


def HOTP(K, C, digits=10):
    """HTOP:
    K is the shared key
    C is the counter value
    digits control the response length
    """
    K_bytes = K.encode()
    C_bytes = struct.pack(">Q", C)
    hmac_sha512 = hmac.new(key=K_bytes, msg=C_bytes,
                           digestmod=hashlib.sha512).hexdigest()
    return Truncate(hmac_sha512)[-digits:]


def Truncate(hmac_sha512):
    """truncate sha512 value"""
    offset = int(hmac_sha512[-1], 16)
    binary = int(hmac_sha512[(offset * 2):((offset*2)+8)], 16) & 0x7FFFFFFF
    return str(binary)


def TOTP(K, digits=10, timeref=0, timestep=30):
    """TOTP, time-based variant of HOTP
    digits control the response length
    the C in HOTP is replaced by ( (currentTime - timeref) / timestep )
    """
    C = int(time.time() - timeref) // timestep

    return HOTP(K, C, digits=digits)


def token_generate():
    print('10 digit token generation using hashing blockcahin technique ')
    start_time = time.time()
    passwd = TOTP(str(random.randint(500, 1000)),
                  random.randint(30, 40), T0, timestep).zfill(10)
    end_time = time.time()
    return (passwd)


states = ["Andhra Pradesh", "Arunachal Pradesh ", "Assam", "Bihar", "Chhattisgarh", "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jammu and Kashmir", "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya", "Mizoram",
          "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal", "Andaman and Nicobar Islands", "Chandigarh", "Dadra and Nagar Haveli", "Daman and Diu", "Lakshadweep", "NCT", "Puducherry"]
# session['user']='Genesis'
'''Blockchain=[{
        'index':'0',
        'patientid':'00000',
        'first': '',
        'last': '',
        'doctor id': '',
        'Dor': '12-13-2019',
        'Age': '',
        'haemo':'',
        'blood':'',


    }]'''

login_status = 0
app = Flask(__name__)
app.secret_key = 'PATREC Authentication'


# Password encryption scheme
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    pbkdf2_sha256__default_rounds=30000
)

# Sessio variables
'''class sessionlog:
    def __init__(self):
        self.username=''
        self.id=''

sess=sessionlog()'''


def encrypt_password(password):
    return pwd_context.hash(password)


def check_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)


# Mongodb setup
# client = pymongo.MongoClient("mongodb+srv://Antony:A8939469555p@blockchainehr-kpbxk.mongodb.net/test?retryWrites=true&w=majority")
# client = pymongo.MongoClient("mongodb+srv://testuser750:mongoDb_750@ehrblock.04zaccd.mongodb.net/?retryWrites=true&w=majority")
# client = pymongo.MongoClient("mongodb+srv://testuser750:mongoDb_750@ehrblock.nvomfgg.mongodb.net/?retryWrites=true&w=majority")
client = pymongo.MongoClient(
    "mongodb+srv://testuser750:mongoDb_750@ehrblock.nvomfgg.mongodb.net/?retryWrites=true&w=majority")
db = client.testuser750
mydb = client["newDB"]


mycol = mydb["Blockhead"]


'''hashset=[]
ind=-1
patdoc= mycol.find()
for x in patdoc:
    hashset.append(x['hash'])
    ind=ind+1

class index:
    index=ind
    def getindex(self):
        self.index=int(self.index+1)
        return self.index

idv=index()'''


# #Apply insurance
@app.route('/apply')
def apply():
    patq = { "_id": session['user'] }#sess.username

    patd= mycol.find_one(patq) # collect details
    if request.method == 'POST':
        aadhar1 = request.form.get['aadhar']
        no1 = request.form.get['no']
        dob1 = request.form.get['dob']
        bill1 = request.form.get['bill']
        fn1 = request.form.get['fn']
        ln1 = request.form.get['ln']
        email1 = request.form.get['email']
        add1 = request.form.get['add']
        mycol.insert_one({'text': aadhar1, 'text': no1, 'date': dob1, 'text': bill1,
                         'text': fn1, 'text': ln1, 'email': email1, 'text': add1})
        return redirect(url_for('apply'))
    return render_template('apply.html',post=patd)

# Doctor account creation


@app.route('/apply1', methods=['post'])
def apply1():
    pat = { "_id": session['user'] }#sess.username
    mycol1 = mydb["Blockhead"]
    patd1= mycol1.find_one(pat)
    if request.method == 'POST':
        pid = request.form['pid']
        name = request.form['aadhar']
        policy = request.form['no']
        date = request.form['dob']
        billamount = request.form['bill']

        first = request.form['fn']
        last = request.form['ln']

        Email = request.form['email']
        adress = request.form['add']
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        mycol = mydb['claim']
        patdoc = mycol.find()
        ind = 0
        for x in patdoc:
            if (x['_id'].find('AD')) != -1:
                ind = ind+1
        insura = {
            '_id': 'AD'+str(ind+1),
            'pid': pid,
            'Addharno': name,
            'policyno': policy,
            'Date': date,
            'Billamount': billamount,
            'First': first,
            'Last': last,
            'email': Email,
            'Address': adress,
            'timestamp': st,
            # 'password':passwd,
        }
        session['user'] = insura['_id']
        # sess.username=doc['_id']
        mycol.insert_one(insura)
    #     Blockc=[]
    #     Bloc=mycol.find()
    #     for i in Bloc:
    #         Blockc.append(i)
    # return render_template('view.html',posts=Blockc)
    return render_template('apply.html',post=patd1)


@app.route('/access1', methods=['POST'])
def access1():
    print('session', session)
    if 'user' not in session:
        return render_template('domain.html')
    
    owner = request.form['PID']
    accessor = session['user']
   
    con = {
        
        'accessor': accessor,
        'owner': owner,
       

    }
   
    transactions = get_transactions(owner)
    
    listData = []
    for i in transactions:
        val = {
            'own': i[0],
            
            'time': datetime.datetime.fromtimestamp(i[1]).strftime('%Y-%m-%d %H:%M:%S')
        }
        listData.append(val)

    print(f"Transactions are : {transactions}")
    print("list data:",listData)
    return render_template('recordchoice1.html', post=con, posts=listData)


@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/learnmore')
def learnmore():
    return render_template('generic.html')

# @app.route('/patview')
# def patview():
#     return render_template('patview.html')


@app.route('/patview', methods=['post', 'get'])
def patview():
    mycol = mydb['claim']
    temp = []
    for x in mycol.find():
        temp.append(x)

    return render_template("patview.html", posts=temp)

    # return render_template('view.html',posts=Blockc)
    # return render_template('view.html')


'''def oldhome():
    return render_template('welcome.html')'''


@app.route('/addguard')
def addguard():
    return render_template('addguard.html')


@app.route('/addguardian', methods=['post'])
def addguardian():
    con = mydb['Guardian_contract']
    contract = {
        'guardian': request.form['guardian'],
        'owner': request.form['owner']
    }
    if (session['user'] == contract['guardian']):
        return 'Contract invalid'
    contract['status'] = 'ACTIVE'
    contract['level'] = request.form['level']
    con.insert_one(contract)
    return redirect(url_for('linkedacc'))


@app.route('/linkedacc')
def linkedacc():
    acc = session['user']
    con = mydb['Guardian_contract']
    contract = {
        'guardian': acc
    }
    myval = con.find(contract)
    mycontro = []
    for i in myval:
        mycontro.append(i)
    contract = {
        'owner': acc
    }
    myval = con.find(contract)
    outcontro = []
    for i in myval:
        outcontro.append(i)
    return render_template('linkedacc.html', mycontrol=mycontro, outcontrol=outcontro)


@app.route('/deleteguard', methods=['post'])
def deleteguard():
    val = dict(request.form)
    myval = mydb['Guardian_contract']
    myval.delete_one(val)
    return redirect(url_for('linkedacc'))

# Organ Donor Card


@app.route('/organ_donor')
def donor():
    return render_template('organ.html')


# Insurance
@app.route('/viewmore')
def doclog1():
    if 'user' in session and session['user'].find('NID') != -1:
        return render_template('docdash1.html')
    else:
        return render_template('doctorlog1.html')


# Doctor credential verification
@app.route('/doclogover1', methods=['POST'])
def doclogver1():
    userid = request.form['DID']
    pwd = request.form['pwd']
    patquery = {"_id": userid}
    myrow = mydb['insurance']
    patdoc = myrow.find(patquery)
    for x in patdoc:
        if check_encrypted_password(pwd, x['password']):
            session['user'] = userid
            # sess.username = userid
            return render_template('docdash1.html')
    return render_template('doctorlog1.html')


# Doctor Access request page
@app.route('/docview1')
def docview1():

    if 'user' in session:
        return render_template('docview1.html')
    else:
        # Unsuccessful login
        return render_template('domain.html')


@app.route('/createcon1', methods=['POST'])
def createcon1():
    if 'user' not in session:
        return render_template('domain.html')

    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    accessor = request.form['accessor']
    owner = request.form['owner']
    record = request.form['record']
    creation = request.form['time']
    con = {
        'accessor': accessor,
        'owner': owner,
        'timestamp': st,
        'record': record,
        'recordcreation': creation,
        'recordtimeperiod': '',
        'flag': 'flag',
        'status': 0

    }
    # myval.insert_one(con)
    return render_template('contractred1.html', posts=con)


@app.route('/back1')
def back1():
    time.sleep(2)
    if 'user' in session:
        if str(session['user']).find('PAT') != -1:
            return render_template('patdash.html')
        if str(session['user']).find('DOC') != -1:
            return render_template('docdash1.html')
        if str(session['user']).find('ADM') != -1:
            return render_template('admindash.html')
        if str(session['user']).find('NID')!=-1:
            return render_template('docdash1.html')
    return render_template('domain.html')


@app.route('/conadd1', methods=['POST'])
def conadd1():
    block = dict(request.form)
    myval = mydb['SMART_CONTRACT']
    query = {'accessor': block['accessor'],
             'owner': block['owner'],
             'record': block['record']}
    che = myval.find_one(query)
    if str(che) == 'None':
        myval.insert_one(block)
    # return redirect(url_for('back1'))
    return render_template('docdash1.html')


@app.route('/available1')
def available1():
    if 'user' not in session:
        return render_template('domain.html')
    myquery = {"accessor": session['user']}
    myview = mydb['SMART_CONTRACT']
    Blockc = []
    Block = []
    ''' rec={
        'doc':'Pending',
        'gluc':0,
        'glucf':0,
        'serum':0,
        'blood':0,
        'chol': 0,
        'thdl':0,
        'ldl':0,
        'rbc':0,
        'pulse':'',
        'timestamp':'',
        'prev': '0',
        'hash':'Pending'
    }'''
    # mydat = myview.find(myquery)  # Smart contract
    # for x in mydat:
    #     mydata = mydb[x['owner']]  # record of patient
    #     mycl = mydata.find()
    #     for y in mycl:
    #         if x['record'] == y['_id']:
    #             if x['status'] == 1:
    #                 Blockc.append(y)
    #             else:
    #                 Block.append(y)

    mydat = myview.find(myquery)  # Smart contract
    for x in mydat:
        # print('X ', x)
        # if x['record'] == y['_id']:
        if x['status'] == 1:
            Blockc.append(x)
        else:
            Block.append(x)
        # mydata = mydb[x['owner']]  # record of patient
        # mycl = mydata.find()
        # for y in mycl:
        #     # print('mycl', y)
        #     if x['record'] == y['_id']:
        #         if x['status'] == 1:
        #             Blockc.append(y)
        #         else:
        #             Block.append(y)

    return render_template('available1.html', posts=Blockc, wait=Block)

# #Apply insurance
# @app.route('/apply')
# def apply():

#     return render_template('apply.html')


@app.route('/patcreate1', methods=['POST'])
def patcreate1():
    if 'user' not in session:
        return render_template('domain.html')
    block_data = request.form['usr']
    aadhar = request.form['aadhar']
    policynumber = request.form['no']
    birthdate = request.form['dob']
    billamont = request.form['bill']
    firstname = request.form['fn']
    lastname = request.form['ln']
    email = request.form['email']
    addres = request.form['add']
    Single = request.form['single']
    Married = request.form['married']
    '''
     try:
        statecode='0'+str(state.index(state))
    except:
        statecode='040
    '''

    # ts=time.time()
    now = datetime.datetime.now()
    # st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    st = now.strftime("%Y-%m-%d %H:%M:%S")
    myrow = mydb['Blockhead']
    patdoc = myrow.find()
    ind = -1
    for x in patdoc:
        prev = x['hash']
        ind = ind+1

    i = 'PAT00'+str(ind+1)
    block = {
        '_id': i,
        'timestamp': st,
        'aadhar': aadhar,
        'policynumber': policynumber,
        'birthdate': birthdate,
        'billamont': billamont,
        'firstname': firstname,
        'lastname': lastname,
        'email': email,
        'addres': addres,
        'Single': Single,
        'Married': Married,
        'prevhash': "prev"

    }
    block_string = json.dumps(block, sort_keys=True)
    print('block_string:::', block_string)
    hashval = sha256(block_string.encode()).hexdigest()
    session['user'] = i
    block = {
        '_id': i,
        'timestamp': st,
        'aadhar': aadhar,
        'policynumber': policynumber,
        'birthdate': birthdate,
        'billamont': billamont,
        'firstname': firstname,
        'record': i+'REC',
        'lastname': lastname,
        'email': email,
        'addres': addres,
        'Single': Single,
        'Married': Married,
        'prevhash': prev,
        'hash': hashval
    }
    '''
    ima=open(file, "rb")
    f = ima.read()
    b = bytearray(f)'''
    myrow = mydb[i]
    rec = {
        '_id': i+'REC'+'00',
        'doc': '',
        'gluc': 0,
        'glucf': 0,
        'serum': 0,
        'blood': 0,
        'chol': 0,
        'thdl': 0,
        'ldl': 0,
        'rbc': 0,
        'pulse': '',
        'prev': '0',

    }

    myrow.insert_one(rec)
    mycol.insert_one(block)
    # import tfe_encrypted
    # import blockchain

    Blockc = []
    Bloc = mycol.find()
    for i in Bloc:
        Blockc.append(i)
    return render_template('apply.html', posts=Blockc)


'''
#MEDREC form creation
@app.route('/create', methods=['POST'])
def createblock():
    pid=request.form['pid']
    doc= request.form['doc']
    blood= request.form['blood']
    pp= request.form['pp']
    fast= request.form['fast']
    serum= request.form['serum']
    tot=request.form['tot']
    thdl=request.form['thdl']
    ldl=request.form['ldl']
    rbc=request.form['rbc']
    pulse=request.form['pulse']
    myrow=mydb[pid]
    patdoc= myrow.find()
    ind=-1
    for x in patdoc:
        prev=x['hash']
        ind=ind+1
    ts=time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    block={
        '_id':pid+'REC'+str(ind+1),
        'owner':pid,
        'doc':doc,
        'gluc':pp,
        'glucf':fast,
        'serum':serum,
        'blood':blood,
        'chol': tot,
        'thdl':thdl,
        'ldl':ldl,
        'rbc':rbc,
        'pulse':pulse,
        'prev': prev,
        'timestamp':st


    }

    block_string = json.dumps(block, sort_keys=True)
    hashval=sha256(block_string.encode()).hexdigest()
    block={
        '_id': pid+'REC'+str(ind+1),
        'owner':pid,
        'doc':doc,
        'gluc':pp,
        'glucf':fast,
        'serum':serum,
        'blood':blood,
        'chol': tot,
        'thdl':thdl,
        'ldl':ldl,
        'rbc':rbc,
        'pulse':pulse,
        'prev': prev,
        'hash':hashval,
        'timestamp':st

    }
    myrow.insert_one(block)
    return render_template('newrec.html',post=block)


#Options to create record
@app.route('/medrecord')
def medrecord():
    return render_template('medrecord.html')
'''


# Different medical records
@app.route('/medrecord')
# @app.route('/main')
def medmain():
    return render_template('main.html')


# General medical record
@app.route('/gen')
def gen():
    return render_template('gen.html')


@app.route('/genadd', methods=['post'])
def genadd():
    pid = request.form['pid']
    # myrow = mydb[pid]
    # patdoc = myrow.find()
    # ind = -1
    # prevs = 0
    # for x in patdoc:
    #     prevs = x['hash']
    #     ind = ind+1

    # ts=time.time()
    # st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    now = datetime.datetime.now()
    st = now.strftime("%Y-%m-%d %H:%M:%S")
    transactions = get_transactions(pid)
    record_index = 1

    if len(transactions) > 0:
        index = len(transactions) - 1
        record_index = transactions[index][0]
        record_index = record_index.split('REC')
        record_index = int(record_index[1]) + 1

    # block = {
    #     '_id': pid+'REC'+str(record_index),
    #     'owner': pid,
    #     'type': 'General information',
    #     'creator': session['user'],
    #     'gender': request.form['gen'],
    #     'Age': request.form['age'],
    #     'Weight': request.form['wt'],
    #     'height': request.form['ht'],
    #     'BMI': request.form['bmival'],
    #     'Blood_grp': request.form['blood'],
    #     'BP': request.form['bp'],
    #     'Diabetes': request.form['si'],
    #     'Food_allergies': request.form['nah'],
    #     'prev': prevs,
    #     'timestamp': st
    # }
    # block_string = json.dumps(block, sort_keys=True)
    # hashval = sha256(block_string.encode()).hexdigest()
    block = {
        '_id': pid+'REC'+str(record_index),
        'owner': pid,
        'type': 'General information',
        'creator': session['user'],
        'gender': request.form['gen'],
        'Age': request.form['age'],
        'Weight': request.form['wt'],
        'height': request.form['ht'],
        'BMI': request.form['bmival'],
        'Blood_grp': request.form['blood'],
        # 'Blood_type':request.form['pos'],
        'BP': request.form['bp'],
        'Diabetes': request.form['si'],
        'Food_allergies': request.form['nah'],
        # 'hash': hashval,
        # 'prev': prevs,
        'timestamp': st
    }
    type = 'genadder'
    return render_template('disp.html', posts=block, direct=type)


@app.route('/genadder', methods=['post'])
def genadder():
    pid = request.form['owner']
    # now = datetime.datetime.now()
    # st=now.strftime("%Y-%m-%d %H:%M:%S")
    # block={
    #     '_id':request.form['_id'],
    #     'owner':pid,
    #     'type':'General information',
    #     'creator':session['user'],
    #     'gender': request.form['gender'],
    #     'Age':request.form['Age'],
    #     'Weight':request.form['Weight'],
    #     'height':request.form['height'],
    #     'BMI':request.form['BMI'],
    #     'Blood_grp':request.form['Blood_grp'],
    #     #'Blood_type':request.form['Blood_type'],
    #     'BP':request.form['BP'],
    #     'Diabetes':request.form['Diabetes'],
    #     'Food_allergies':request.form['Food_allergies'],
    #     'hash':request.form['hash'],
    #     'prev': request.form['prev'],
    #     'timestamp':st }
    # myrow=mydb[pid]
    # myrow.insert_one(block)

    record_id = request.form['_id']

    diabetes_flag = True if request.form['Diabetes'] == 'Yes' else False
    allergy_flag = True if request.form['Food_allergies'] == 'Yes' else False

    tranaction_hash = create_transaction(pid, record_id, request.form['gender'], int(request.form['Weight']), request.form['height'],
                                         'Analysis', request.form['Blood_grp'], request.form['BP'],
                                         request.form['BMI'], int(request.form['Age']), bool(diabetes_flag), bool(allergy_flag))

    print(f"The transaction hash is : {tranaction_hash}")
    return redirect(url_for('back'))


# Basic clinical details
@app.route('/bioc')
def bioc():
    return render_template('bioc.html')


@app.route('/biocadd', methods=['post'])
def biocadd():
    pid = request.form['pid']
    myrow = mydb[pid]
    patdoc = myrow.find()
    ind = -1
    prevs = 0
    for x in patdoc:
        prevs = x['hash']
        ind = ind+1

    # ts=time.time()
    # st = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    now = datetime.datetime.now()
    st = now.strftime("%Y-%m-%d %H:%M:%S")
    block = {
        '_id': pid+'REC'+str(ind+1),
        'owner': pid,
        'type': 'Clinical Laboratory information',
        'creator': session['user'],
        'Haemoglobin (g/dL)': request.form['hdl'],
        'Glucose (random PP)': request.form['glr'],
        'Glucose (fasting)': request.form['glf'],
        # 'HbA1c (EDTA Blood)':request.form['hba1c'],
        'SERUM Appearance': request.form['seum'],
        'Total Cholestrol': request.form['tch'],
        'Triglycerides': request.form['try'],
        'HDL Cholestrol': request.form['hch'],
        'LDL Cholestrol': request.form['lch'],
        'VLDL': request.form['vldl'],
        'CHOL / HDL Ratio': request.form['chol'],
        'Colour': request.form['colo'],
        'Apperance': request.form['coloo'],
        'PH': request.form['ph'],
        'Protein': request.form['pro'],
        'Sugar': request.form['sug'],
        'Bile Salt': request.form['bsal'],
        'Bile Pigment': request.form['bpig'],
        'prev': prevs,
        'timestamp': st
    }
    block_string = json.dumps(block, sort_keys=True)
    hashval = sha256(block_string.encode()).hexdigest()
    block = {
        '_id': pid+'REC'+str(ind+1),
        'owner': pid,
        'type': 'Clinical Laboratory information',
        'creator': session['user'],
        'Haemoglobin': request.form['hdl'],
        'Random_PP': request.form['glr'],
        'Fasting': request.form['glf'],
        # 'HbA1c (EDTA Blood)':request.form['hbalc'],
        'SERUM Appearance': request.form['seum'],
        'Cholestrol': request.form['tch'],
        'Triglycerides': request.form['try'],
        'HDLCholestrol': request.form['hch'],
        'LDLCholestrol': request.form['lch'],
        'VLDL': request.form['vldl'],
        # 'CHOL / HDL Ratio':request.form['chol'],
        'Colour': request.form['colo'],
        'Apperance': request.form['coloo'],
        'PH': request.form['ph'],
        'Protein': request.form['pro'],
        'Sugar': request.form['sug'],
        'BileSalt': request.form['bsal'],
        'BilePigment': request.form['bpig'],
        'hash': hashval,
        'prev': prevs,
        'timestamp': st}
    type = 'biocadder'
    return render_template('disp.html', posts=block, direct=type)


@app.route('/biocadder', methods=['post'])
def biocadder():
    pid = request.form['owner']
    block = {
        '_id': request.form['_id'],
        'owner': pid,
        'type': 'Clinical Laboratory information',
        'creator': session['user'],
        'Haemoglobin': request.form['Haemoglobin'],
        # 'Random_PP':request.form['Random_PP'],
        # 'Fasting':request.form['Fasting'],
        # 'HbA1c (EDTA Blood)':request.form['HbA1c (EDTA Blood)'],
        # 'SERUM_Appearance':request.form['SERUM_Appearance'],
        # 'Cholestrol':request.form['Cholestrol'],
        'Triglycerides': request.form['Triglycerides'],
        'HDLCholestrol': request.form['HDLCholestrol'],
        'LDLCholestrol': request.form['LDLCholestrol'],
        'VLDL': request.form['VLDL'],
        # 'CHOL/HDL Ratio':request.form['CHOL / HDL Ratio'],
        'Colour': request.form['Colour'],
        'Apperance': request.form['Apperance'],
        'PH': request.form['PH'],
        'Protein': request.form['Protein'],
        'Sugar': request.form['Sugar'],
        'BileSalt': request.form['BileSalt'],
        'BilePigment': request.form['BilePigment'],
        'hash': request.form['hash'],
        'prev': request.form['prev'],
        'timestamp': request.form['timestamp']}
    myrow = mydb[pid]
    myrow.insert_one(block)
    return redirect(url_for('back'))


# Cardiac details
@app.route('/cardiac')
def cardiac():
    return render_template('cardiac.html')


@app.route('/cardiacadd', methods=['post'])
def cardiacadd():
    pid = request.form['pid']
    myrow = mydb[pid]
    patdoc = myrow.find()
    ind = -1
    prevs = 0
    f = request.files['ECG']
    g = request.files['EST']
    h = request.files['ECHOCARDIO']
    an = request.files['ANG']
    '''
    if f.filename!='':
        f.save(secure_filename(f.filename))
        try:
            api = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')
            new_file = api.add(f.filename)
        except ipfshttpclient.exceptions.ConnectionError as ce:
            new_file['hash']=''
    else:
        new_file['hash']=''
    #new_file['hash']=''
    '''
    for x in patdoc:
        prevs = x['hash']
        ind = ind+1
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    block = {
        '_id': pid+'REC'+str(ind+1),
        'owner': pid,
        'type': 'Cardiac Report',
        'creator': session['user'],
        'CHOLESTROL': request.form['cho'],
        'TRIGYCERIDES': request.form['tri'],
        'ECG': f.filename,
        'EST': g.filename,
        'ECHOCARDIO': h.filename,
        'ANGIOGRAM': an.filename,
        'prev': prevs,
        'timestamp': st}
    block_string = json.dumps(block, sort_keys=True)
    hashval = sha256(block_string.encode()).hexdigest()
    if f.filename != '':
        f.save(secure_filename(f.filename))
    if g.filename != '':
        g.save(secure_filename(g.filename))
    if h.filename != '':
        h.save(secure_filename(h.filename))
    if an.filename != '':
        an.save(secure_filename(an.filename))
    try:
        api = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')
        if block['ECG'] != '':
            new_file = api.add(block['ECG'])
            block['ECGSCAN'] = str(new_file['Hash'])
        if block['EST'] != '':
            new_file = api.add(block['EST'])
            block['ESTSCAN'] = str(new_file['Hash'])
        if block['ANGIOGRAM'] != '':
            new_file = api.add(block['ANGIOGRAM'])
            block['ANGSCAN'] = str(new_file['Hash'])
        if block['ECHOCARDIO'] != '':
            new_file = api.add(block['ECHOCARDIO'])
            block['ECGSCAN'] = str(new_file['Hash'])
        # link='http://localhost:8080/ipfs/'+str(new_file['Hash'])
        # webbrowser.open(link)
    except ipfshttpclient.exceptions.ConnectionError as ce:
        error = 'Could not add files'

    block['hash'] = hashval
    type = 'cardiacadder'
    return render_template('disp.html', posts=block, direct=type)


@app.route('/cardiacadder', methods=['post'])
def cardiacadder():
    '''{
        '_id':request.form['_id'],
        'owner':request.form['owner'],
        'type':'Cardiac Report',
        'creator':session['user'],
        'CHOLESTROL': request.form['CHOLESTROL'],
        'TRIGYCERIDES':request.form['TRIGYCERIDES'],
        'ECG': request.form['ECG'],
        'hash':request.form['hash'],
        'prev': request.form['prev'],
        'timestamp':request.form['timestamp']}'''

    block = dict(request.form)
    myrow = mydb[request.form['owner']]
    myrow.insert_one(block)
    return redirect(url_for('back'))


@app.route('/qrcode')
def qrcode():
    return render_template('qrcode.html')

# Dermatology details


@app.route('/derm')
def derm():
    return render_template('derm.html')

# @app.route('/ortho')
# def ortho():
#     return render_template('ortho.html')


# Login options page

@app.route('/domain')
def domain():
    return render_template('domain.html')


# Signup options page
@app.route('/signup')
def signup():
    return render_template('signup.html')


# PATIENT

# Patient signup
@app.route('/patient')
def patient():
    return render_template('patient.html')

# Patient Login


@app.route('/patientlog')
def patientlog():
    if 'user' in session and str(session['user']).find('PAT') != -1:
        return render_template('patdash.html')
    else:
        return render_template('patientlog.html')


# Patient Credential verification
@app.route('/patientver', methods=['POST'])
def patientverify():
    userid = request.form['PID']
    pwd = request.form['pwd']
    patquery = {"_id": userid}

    patdoc = mycol.find(patquery)
    for x in patdoc:
        if check_encrypted_password(pwd, x['passwd']):
            # sess.username = userid
            session['user'] = userid
            return render_template('patdash.html')

    return render_template('patientlog.html')

# PAtient acc creation with credentials


@app.route('/patcreate', methods=['POST'])
def patcreate():
    block_data = request.form['usr']
    first = request.form['usr']
    second = request.form['lsn']
    passwd = request.form['pwd']
    passwd = encrypt_password(passwd)
    addres = request.form['addres']
    age = request.form['age']
    city = request.form['city']
    state = request.form['state']
    '''
     try:
        statecode='0'+str(state.index(state))
    except:
        statecode='040
    '''
    aadhar = request.form['Aadhar']
    # ts=time.time()
    now = datetime.datetime.now()
    # st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    st = now.strftime("%Y-%m-%d %H:%M:%S")
    myrow = mydb['Blockhead']
    patdoc = myrow.find()
    ind = -1
    for x in patdoc:
        prev = x['hash']
        ind = ind+1

    i = 'PAT00'+str(ind+1)
    block = {
        '_id': i,
        'timestamp': st,
        'first': first,
        'second': second,
        'passwd': passwd,
        'address': addres,
        'city': city,
        'state': state,
        'aadhar': aadhar,
        'prevhash': "prev"
    }
    block_string = json.dumps(block, sort_keys=True)
    print('block_string:::', block_string)
    hashval = sha256(block_string.encode()).hexdigest()
    session['user'] = i
    block = {
        '_id': i,
        'timestamp': st,
        'first': first,
        'second': second,
        'passwd': passwd,
        'address': addres,
        'record': i+'REC',
        'city': city,
        'state': state,
        'aadhar': aadhar,
        'prevhash': prev,
        'hash': hashval
    }
    '''
    ima=open(file, "rb")
    f = ima.read()
    b = bytearray(f)'''
    myrow = mydb[i]
    rec = {
        '_id': i+'REC'+'00',
        'doc': '',
        'gluc': 0,
        'glucf': 0,
        'serum': 0,
        'blood': 0,
        'chol': 0,
        'thdl': 0,
        'ldl': 0,
        'rbc': 0,
        'pulse': '',
        'prev': '0',

    }
    # import tfe_encrypted
    # import blockchain
    block_s = json.dumps(rec, sort_keys=True)
    hashrec = sha256(block_s.encode()).hexdigest()
    rec = {
        '_id': i+'REC'+'00',
        'doc': '',
        'type': 'none',
        'gluc': 0,
        'glucf': 0,
        'serum': 0,
        'blood': 0,
        'chol': 0,
        'thdl': 0,
        'ldl': 0,
        'rbc': 0,
        'pulse': '',
        'timestamp': '',
        'prev': '0',
        'hash': hashrec

    }

    myrow.insert_one(rec)
    mycol.insert_one(block)
    import tfe_encrypted
    import blockchain

    Blockc = []
    Bloc = mycol.find()
    for i in Bloc:
        Blockc.append(i)
    return render_template('patcreate.html', posts=Blockc)
    # import tfe_encrypted
    # import blockchain


# Patient dashboard welcome page
@app.route('/patdash')
def patdash():
    if 'user' in session:
        return render_template('patdash.html')
    else:
        # Login unsuccessful
        return render_template('domain.html')


# Display patient user info
@app.route('/patacc')
def views():
    patquery = {"_id": session['user']}  # sess.username

    patdoc = mycol.find_one(patquery)

    return render_template('patmyacc.html', post=patdoc)

# View current patient's record


@app.route('/viewrec', methods=['POST'])
def viewrec():
    s = request.form['owner']
    myrow = mydb[s]  # change
    recs = myrow.find()
    records = []
    for x in recs:
        records.append(x)
    return render_template('records.html', posts=records)


# Doctor

# Doctor signup
@app.route('/doctor')
def doctor():
    return render_template('doctor.html')

# Insurance signup

@app.route('/insurancein_out')
def insurancenew():
    return render_template("insurancein_out.html")


@app.route('/doctor1')
def doctor1():
    return render_template('doctor1.html')


@app.route('/docver1', methods=['POST'])
def docverify1():

    name = request.form['doc']
    company = request.form['nm']
    # address=request.form['add']
    # qualification=request.form['qualific']
    # study=request.form['grad']
    # workcontact=request.form['num']
    contact = request.form['no']
    password = request.form['pwd']
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    passwd = request.form['pwd']
    passwd = encrypt_password(passwd)
    myrow = mydb['insurance']
    patdoc = myrow.find()
    ind = 0
    for x in patdoc:
        if (x['_id'].find('NID')) != -1:
            ind = ind+1
    doc = {
        '_id': 'NID'+str(ind+1),
        'Insurancename': name,
        'company': company,
        # 'address' : address,
        # 'qualification': qualification,
        # 'edufrom' : study,
        # 'appointment': workcontact,
        'contact': contact,
        'timestamp': st,
        'password': passwd,
    }
    session['user'] = doc['_id']
    # sess.username=doc['_id']
    myrow.insert_one(doc)
    return render_template('doctor1.html')

# Doctor Login


@app.route('/doclog')
def doclog():
    if 'user' in session and session['user'].find('DOC') != -1:
        return render_template('docdash.html')
    else:
        return render_template('doctorlog.html')

# Doctor credential verification


@app.route('/doclogover', methods=['POST'])
def doclogver():
    userid = request.form['DID']
    pwd = request.form['pwd']
    patquery = {"_id": userid}
    myrow = mydb['Nodes']
    patdoc = myrow.find(patquery)
    for x in patdoc:
        if check_encrypted_password(pwd, x['password']):
            session['user'] = userid
            # sess.username = userid
            return render_template('docdash.html')
    return render_template('doctorlog.html')

# Doctor account creation


@app.route('/docver', methods=['POST'])
def docverify():

    name = request.form['doc']
    specialization = request.form['special']
    address = request.form['add']
    qualification = request.form['qualific']
    study = request.form['grad']
    workcontact = request.form['num']
    personal = request.form['n']
    about = request.form['more']
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    passwd = request.form['pwd']
    passwd = encrypt_password(passwd)
    myrow = mydb['Nodes']
    patdoc = myrow.find()
    ind = 0
    for x in patdoc:
        if (x['_id'].find('DOC')) != -1:
            ind = ind+1
    doc = {
        '_id': 'DOC'+str(ind+1),
        'docname': name,
        'specialization': specialization,
        'address': address,
        'qualification': qualification,
        'edufrom': study,
        'appointment': workcontact,
        'number': personal,
        'moreabout': about,
        'timestamp': st,
        'password': passwd,
    }
    session['user'] = doc['_id']
    # sess.username=doc['_id']
    myrow.insert_one(doc)
    return render_template('docdash.html')


# Doctor dashboard
@app.route('/docdash')
def docdash():
    if 'user' in session and str(session['user']).find('DOC') != -1:
        return render_template('docdash.html')
    else:
        # Unsuccessful login
        return render_template('domain.html')

# Doctor Access request page


@app.route('/docview')
def docview():
    if 'user' in session:
        return render_template('docview.html')
    else:
        # Unsuccessful login
        return render_template('domain.html')


# Account info
@app.route('/myacc')
def myacc():
    if 'user' not in session:
        return render_template('domain.html')
    patquery = {"_id": session['user']}
    myrow = mydb['Nodes']
    patdoc = myrow.find_one(patquery)
    del patdoc['password']
    return render_template('myacc.html', post=patdoc)


@app.route('/access', methods=['POST'])
def access():
    print('session', session)
    if 'user' not in session:
        return render_template('domain.html')
    owner = request.form['PID']
    accessor = session['user']
    '''url = "https://www.fast2sms.com/dev/bulk"

    querystring = {"authorization":"4FzGm7K6haHIMiAJfuNsSwv50rT8cROE2UBCkP9yp3bZdXDlQqC0jLU1HVkQYE3sNdph24AIztabBcTO","sender_id":"PATREC","language":"english","route":"qt","numbers":"9789862702","message":"Doctor has requested for your record."}

    headers = {
    'cache-control': "no-cache"
    }

    response=requests.request("GET", url, headers=headers, params=querystring)'''
    # myval=mydb['SMART_CONTRACT']
    # ts=time.time()
    # st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    con = {
        'accessor': accessor,
        'owner': owner,
        # 'timestamp':st,
        # 'record':owner+'REC',
        # 'status':0

    }
    # lists = []
    # myval = mydb[owner]
    # myvalue = myval.find()

    # myval2 = mydb['SMART_CONTRACT']
    # myvalue2 = myval2.find()

    # for i in myvalue:
    #     val = {
    #         'own': i['_id'],
    #         'time': i['timestamp']}
    #     lists.append(val)

    transactions = get_transactions(owner)

    listData = []
    for i in transactions:
        val = {
            'own': i[0],
            # 'gender': i[2],
            # 'currentWeight': i[3],
            # 'currentHeight': i[4],
            # 'analysis': i[5],
            # 'bloodDetails': i[6],
            # 'bp': i[7],
            # 'bmi': i[8],
            # 'age': i[9],
            # 'isDiabetic': i[10],
            # 'isAllergic': i[11],
            'time': datetime.datetime.fromtimestamp(i[1]).strftime('%Y-%m-%d %H:%M:%S')
        }
        listData.append(val)

    print(f"Transactions are : {transactions}")

    # return render_template('recordchoice.html', post=con, posts=lists)
    return render_template('recordchoice.html', post=con, posts=listData)


@app.route('/createcon', methods=['POST'])
def createcon():
    if 'user' not in session:
        return render_template('domain.html')

    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    accessor = request.form['accessor']
    owner = request.form['owner']
    record = request.form['record']
    creation = request.form['time']
    con = {
        'accessor': accessor,
        'owner': owner,
        'timestamp': st,
        'record': record,
        'recordcreation': creation,
        'recordtimeperiod': '',
        'flag': 'flag',
        'status': 0

    }
    # myval.insert_one(con)
    return render_template('contractred.html', posts=con)


@app.route('/back')
def back():
    time.sleep(2)
    if 'user' in session:
        if str(session['user']).find('PAT') != -1:
            return render_template('patdash.html')
        if str(session['user']).find('DOC') != -1:
            return render_template('docdash.html')
        if str(session['user']).find('ADM') != -1:
            return render_template('admindash.html')
    return render_template('domain.html')


@app.route('/display', methods=['post'])
def display():
    if 'user' not in session:
        return render_template('domain.html')
    block = {
        '_id': request.form['_id']

    }
    tokenverify = mydb['SMART_CONTRACT']
    token = request.form['token']
    t1 = tokenverify.find_one(
        {'record': request.form['_id'], 'accessor': session['user']})
    # print(t1)

    if t1['flag'] == token:
        # print(t1['flag'])
        timerecord = t1['recordtimeperiod']
        datetime_object = datetime.datetime.strptime(
            timerecord, '%Y-%m-%d %H:%M')
        if datetime_object > datetime.datetime.now():
            transaction = get_transaction_by_record_id(
                request.form['owner'], request.form['_id'])
            # print(f"Transaction ---------------------- {transaction}")
            # mycol = mydb[request.form['owner']]
            # myview = mycol.find_one(block)
            # print(f"View Data --- {myview}")
            if len(transaction) > 0:
                data = transaction[0]
                owner = data[0].split('REC')
                owner = owner[0]
                Diabetes = 'Yes' if data[10] == True else 'No'
                Food_allergies = 'Yes' if data[11] == True else 'No'
                mydata = {
                    '_id': data[0],
                    'owner': owner,
                    'type': 'General Information',
                    # 'creator': 'DOC25',
                    'timestamp': datetime.datetime.fromtimestamp(data[1]).strftime('%Y-%m-%d %H:%M:%S'),
                    'gender': data[2],
                    'Weight': data[3],
                    'height': data[4],
                    # 'Analysis': data[5],
                    'Blood_grp': data[6],
                    'BP': data[7],
                    'BMI': data[8],
                    'Age': data[9],
                    'Diabetes': Diabetes,
                    'Food_allergies': Food_allergies
                }
                return render_template('individualrec.html', post=mydata)
        else:
            msg = 'Token Expired on ' + \
                str(datetime_object) + \
                '\nRaise request again to get  to this record '
            return msg
    else:
        return 'Incorrect or expired token. Go back and enter again correct token'

    return redirect(url_for('back'))


@app.route('/display1', methods=['post'])
def display1():
    if 'user' not in session:
        return render_template('domain.html')
    block = {
        '_id': request.form['_id']

    }
    tokenverify = mydb['SMART_CONTRACT']
    token = request.form['token']
    t1 = tokenverify.find_one(
        {'record': request.form['_id'], 'accessor': session['user']})
    # print(t1)
    if t1['flag'] == token:
        # print(t1['flag'])
        timerecord = t1['recordtimeperiod']
        datetime_object = datetime.datetime.strptime(
            timerecord, '%Y-%m-%d %H:%M')
        if datetime_object > datetime.datetime.now():
            # mycol = mydb['claim']
            # myview = mycol.find_one({'pid': request.form['owner']})
            # if myview:
            transaction = get_transaction_by_record_id(
                request.form['owner'], request.form['_id'])
            # print(f"Transaction ---------------------- {transaction}")
            # mycol = mydb[request.form['owner']]
            # myview = mycol.find_one(block)
            # print(f"View Data --- {myview}")
            if len(transaction) > 0:
                data = transaction[0]
                owner = data[0].split('REC')
                owner = owner[0]
                Diabetes = 'Yes' if data[10] == True else 'No'
                Food_allergies = 'Yes' if data[11] == True else 'No'
                mydata = {
                    '_id': data[0],
                    'owner': owner,
                    'type': 'General Information',
                    # 'creator': 'DOC25',
                    'timestamp': datetime.datetime.fromtimestamp(data[1]).strftime('%Y-%m-%d %H:%M:%S'),
                    'gender': data[2],
                    'Weight': data[3],
                    'height': data[4],
                    # 'Analysis': data[5],
                    'Blood_grp': data[6],
                    'BP': data[7],
                    'BMI': data[8],
                    'Age': data[9],
                    'Diabetes': Diabetes,
                    'Food_allergies': Food_allergies
                }
                return render_template('individualrec1.html', post=mydata)
        else:
            msg = 'Token Expired on ' + \
                str(datetime_object) + \
                '\nRaise request again to get  to this record '
            return msg
    else:
        return 'Incorrect or expired token. Go back and enter again correct token'

    return redirect(url_for('back1'))


@app.route('/share', methods=['post'])
def sharee():
    if 'user' not in session:
        return render_template('domain.html')
    block = dict(request.form)
    return render_template('patientview.html', post=block)


@app.route('/sharerec', methods=['post'])
def sharerec():
    if 'user' not in session:
        return render_template('domain.html')

    myval = mydb['SMART_CONTRACT']
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    accessor = request.form['accessor']
    owner = request.form['owner']
    record = request.form['_id']
    # creation=request.form['time']
    con = {
        'accessor': accessor,
        'owner': owner,
        'timestamp': st,
        'record': record,
        # 'recordcreation':creation,
        'status': 1

    }
    # myval.insert_one(con)
    return render_template('contractred.html', posts=con)


@app.route('/conadd', methods=['POST'])
def conadd():
    block = dict(request.form)
    myval = mydb['SMART_CONTRACT']
    query = {'accessor': block['accessor'],
             'owner': block['owner'],
             'record': block['record']}
    che = myval.find_one(query)
    if str(che) == 'None':
        myval.insert_one(block)
    return redirect(url_for('back'))


@app.route("/cancel", methods=['POST'])
def cancel():
    mycol = mydb['SMART_CONTRACT']
    temp = {
        'owner': request.form['owner'],
        'record': request.form['_id'],
        'accessor': request.form['accessor']
    }
    mycol.delete_one(temp)
    # return temp
    return redirect(url_for('available'))


@app.route('/bookapp')
def index():
    return render_template("bookapp.html")


@app.route('/formdis')
def form():
    return render_template("result.html")


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        area = request.form['special']
        mycol = mydb['Nodes']
        temp = {'specialization': area}
        found = mycol.find(temp)
        arr = []
        for i in found:
            arr.append(i)
    return render_template("show.html", posts=arr, special=area)


@app.route('/knowndoctor')
def known():
    return render_template('docinfo.html')


@app.route('/schedule', methods=['POST'])
def schedule():
    docid = request.form['docid']
    mycol = mydb['Nodes']
    nm = request.form['name']
    temp = {'docname': nm}
    f = mycol.find(temp)
    arr = []
    for i in f:
        arr.append(i)
    return render_template("test.html", posts=arr)


@app.route('/appoint')
def appoint():
    # msg="you have an appoinment with from.doc"
    # clientn.send_message({'from' : 'nexmo' , 'to' : '+91 6383230641', 'text' : 'msg'})
    return render_template("booked.html")


# ADMIN -radiologists,lab technicians, hospital staff

# Admin acc creation
@app.route('/hospital')
def hospital():
    return render_template('hospital.html')

# Admin login page


@app.route('/adminlog')
def adminlog():
    if 'user' in session and str(session['user']).find('ADM') != -1:
        return render_template('admindash.html')
        print(user)
    return render_template('hospitallog.html')

# Admin account creation


@app.route('/admver', methods=['POST'])
def admverify():
    nam = request.form['n']
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    passwd = request.form['pwd']
    passwd = encrypt_password(passwd)
    myrow = mydb['Nodes']
    patdoc = myrow.find()
    ind = 0
    print(nam)
    for x in patdoc:
        if (x['_id'].find('ADM')) != -1:
            ind = ind+1
    doc = {
        '_id': 'ADM'+str(ind+1),
        'timestamp': st,
        'password': passwd,
        'name': nam
    }
    # sess.username=doc['_id']
    session['user'] = doc['_id']
    myrow.insert_one(doc)
    return render_template('admindash.html')

# Admin account verification


@app.route('/admlogover', methods=['POST'])
def admlogver():
    userid = request.form['AID']
    pwd = request.form['pwd']
    patquery = {"_id": userid}
    myrow = mydb['Nodes']
    patdoc = myrow.find(patquery)
    for x in patdoc:
        if check_encrypted_password(pwd, x['password']):
            session['user'] = userid
            # sess.username = userid
            return render_template('admindash.html')
    return render_template('hospitallog.html')


# Admin dash board
@app.route('/admindash')
def admindash():
    if 'user' in session:
        return render_template('admindash.html')
    return render_template('domain.html')


@app.route('/accesslog')
def accesslog():
    if 'user' not in session:
        return render_template('domain.html')
    mycli = mydb['SMART_CONTRACT']
    query = {"owner": session['user']}
    mydata = mycli.find(query)
    block = []
    for x in mydata:
        block.append(x)
    block.reverse()
    # sess.id=x['accessor']
    return render_template('accesslog.html', posts=block)


@app.route('/available')
def available():
    if 'user' not in session:
        return render_template('domain.html')
    myquery = {"accessor": session['user']}
    myview = mydb['SMART_CONTRACT']
    Blockc = []
    Block = []
    ''' rec={
        'doc':'Pending',
        'gluc':0,
        'glucf':0,
        'serum':0,
        'blood':0,
        'chol': 0,
        'thdl':0,
        'ldl':0,
        'rbc':0,
        'pulse':'',
        'timestamp':'',
        'prev': '0',
        'hash':'Pending'
    }'''
    mydat = myview.find(myquery)  # Smart contract
    for x in mydat:
        # print('X ', x)
        # if x['record'] == y['_id']:
        if x['status'] == 1:
            Blockc.append(x)
        else:
            Block.append(x)
        # mydata = mydb[x['owner']]  # record of patient
        # mycl = mydata.find()
        # for y in mycl:
        #     # print('mycl', y)
        #     if x['record'] == y['_id']:
        #         if x['status'] == 1:
        #             Blockc.append(y)
        #         else:
        #             Block.append(y)

    return render_template('available.html', posts=Blockc, wait=Block)
# bAPP_ROOT = os.path.dirname(os.path.abspath(__file__))


'''@app.route("/upload", methods=['POST'])
def upload():
    target = os.path.join(APP_ROOT, 'images/')

    if not os.path.isdir(target):
        os.mkdir(target)

    for file in request.files.getlist("file"):
        print(file)
        filename = file.filename
        destination = "/".join([target, filename])
        print(destination)
        file.save(destination)

    return render_template("complete.html")'''

mylist = mycol.find_one()
# mylist=mycol.find_one({}, sort=[("position", pymongo.DESCENDING)])
cursor = mycol.find().sort([('timestamp', -1)]).limit(1)
# cursor=mycol.find()db
print("================")
for each_mylist in cursor:
    print(each_mylist)


@app.route('/authorize', methods=['post'])
def authorize():
    if request.form['status'] == 1:
        return redirect(url_for('accesslog'))
    myview = mydb['SMART_CONTRACT']
    tm = request.form['timeperiod']
    tm = tm.replace('T', ' ')
    token_value = token_generate()

    message_str = list(str(each_mylist))
    import tfe_encrypted
    message_str.append(token_value), ' ,share it to doctor'
    print(message_str)
    myquery = {'record': request.form['record'],
               'accessor': request.form['accessor'],
               'owner': session['user']
               }
    newvalues = {"$set": {"status": 1,
                          "recordtimeperiod": tm, "flag": token_value}}
    myview.update_one(myquery, newvalues)
    return redirect(url_for('accesslog'))


@app.route('/deny', methods=['post'])
def decline():
    if request.form['status'] == 0:
        return redirect(url_for('accesslog'))
    myview = mydb['SMART_CONTRACT']
    myquery = {'record': request.form['record'],
               'accessor': request.form['accessor'],
               'owner': session['user']}
    newvalues = {"$set": {"status": 0}}
    myview.update_one(myquery, newvalues)
    return redirect(url_for('accesslog'))


@app.route('/medrec')
def medrec():
    if 'user' in session:
        idv = {'doc': session['user']}
        return render_template('medrec.html', posts=idv)
    else:
        # Unsuccessful login
        return render_template('domain.html')


@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
    return render_template('domain.html')


clienth = pymongo.MongoClient(
    "mongodb+srv://hemapriya:hema1512@medicare-w9kad.gcp.mongodb.net/test?retryWrites=true&w=majority")

mydbh = clienth["blogdetails"]

mycolh = mydbh["medblog"]


@app.route('/medblog')
def medblog():
    return render_template("medblog.html")


@app.route('/new')
def new():
    return render_template("new.html")


@app.route('/result', methods=['POST'])
def result():
    i = 0
    title = request.form['title']
    imgurl = request.form['pic']
    content = request.form['comment']
    today = date.today()
    d = today.strftime("%B %d, %Y")
    onepost = mycolh.find()

    for x in onepost:
        i = i+1
    block = {
        '_id': 'POST'+str(i),
        'title': title,
        'url': imgurl,
        'content': content,
        'time': d
    }
    mycolh.insert_one(block)

    arr = []
    temp = {'title': title}
    f = mycolh.find(temp)
    for i in f:
        arr.append(i)

    return render_template("output.html", posts=arr)


# @app.route('/view')
# def view():

#     mycolh = mydbh["medblog"]
#     temp =[]
#     for x in mycolh.find():
#         temp.append(x)

#     return render_template("allposts.html" , posts=temp)


@app.route("/delete")
def delete():
    return render_template("delete.html")


@app.route("/deletepost", methods=['POST'])
def deletepost():
    pid = request.form['pid']
    tit = request.form['title']
    arr = []
    temp = {'_id': pid}
    found = mycolh.find(temp)

    for k in found:
        arr.append(k)

    mycolh.delete_one(temp)

    return render_template("deleted.html", posts=arr)


@app.route('/update')
def update():
    return render_template("update.html")


@app.route('/updatepost', methods=['POST'])
def updatepost():
    pid = request.form['pid']
    content = request.form['comment']
    temp = {'_id': pid}
    change = {"$set": {'content': content}}

    mycolh.update_one(temp, change)

    arr = []
    temp = {'_id': pid}
    found = mycolh.find(temp)

    for k in found:
        arr.append(k)

    return render_template("updatedpost.html", posts=arr)


if __name__ == '__main__':
    app.run(port=int(os.environ.get('PORT', 5000)))
