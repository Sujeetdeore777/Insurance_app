import pymongo

doc={
    '_id':'ADM00' ,
    'name':'',
    'passwd': '1234',
    'timestamp':'0'
}


#client = pymongo.MongoClient("mongodb+srv://Antony:A8939469555@blockchainehr-kpbxk.mongodb.net/test?retryWrites=true&w=majority")
client = pymongo.MongoClient("mongodb+srv://testuser750:mongoDb_750@ehrblock.nvomfgg.mongodb.net/?retryWrites=true&w=majority")
db = client.testuser750
mydb=client["Blockchain"]

mycol=mydb["Nodes"]


y=mycol.insert_one(doc)
print(y)