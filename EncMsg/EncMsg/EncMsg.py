

#Cai dat key RSA da su dung o bai tap thuc hanh viet bang C++, o day em chi cai dat AES va su dung thu vien HASH MD5
import Crypto.Util.number
from Crypto.Hash import MD5
import os
import sys
import secrets
import random
import base64
from AES import *
def _string_to_bytes(text):
    return list(ord(c) for c in text)

def _bytes_to_string(binary):
    return "".join(chr(b) for b in binary)

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a



def RSA_KEY_GEN():
    bits=1024
    if (len(sys.argv)>1):
            bits=int(sys.argv[1])
    p=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    q=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    N=p*q
    PHI=(p-1)*(q-1)
    i = random.randrange(258, N)
    while gcd(i, PHI) != 1 :
        i += 1
    e = i
    d=Crypto.Util.number.inverse(e,PHI)
    return (N,e,d)

def UploadPublicKey(user):
    if not os.path.exists("cloud"):
        os.mkdir("cloud")
    with open("cloud/E_"+ user.name +".txt", "w") as f:
        f.write(str(user.E)+" "+str(user.N))
def SaveAllKey(user):
    with open(user.name+"/E.txt", "w") as f:
        f.write(str(user.E))
    with open(user.name+"/D.txt", "w") as f:
        f.write(str(user.D))
    with open(user.name+"/N.txt", "w") as f:
        f.write(str(user.N))
    with open(user.name+"/K.txt", "w") as f:
        f.write(str(user.K))
def ReadAllKey(user):
    with open(user.name+"/E.txt", "r") as f:
        user.E = int(f.read())
    with open(user.name+"/D.txt", "r") as f:
        user.D = int(f.read())
    with open(user.name+"/N.txt", "r") as f:
        user.N = int(f.read())
    with open(user.name+"/K.txt", "r") as f:
        user.K = f.read()

class Users:
    def __init__(self,id):
        self.name = id
        if not os.path.exists(self.name):
            os.mkdir(self.name)
            self.N,self.E, self.D = RSA_KEY_GEN();
            self.K = secrets.token_hex(32)
            SaveAllKey(self)
            
        else:
            ReadAllKey(self)
        UploadPublicKey(self)

    def genNewKey(self):
        self.N,self.E, self.D = RSA_KEY_GEN();
        self.K = secrets.token_hex(32)
        SaveAllKey(self)
        UploadPublicKey(self)

    def RSA_enc(self,msg,e,n):

        key_list = []
        for i in msg:
           ascii_char = ord(i)
           key = pow(ascii_char,e,n)
           key_list.append(key)

        return key_list

    def RSA_dec(self,enc,d,n):
        key_list = []
        for i in enc:
            key_char = pow(int(i),d,n)
            ascii_key = chr(key_char)
            key_list.append(ascii_key)
        return key_list

    def MD5_hash(self,msg):
        md5_hash = MD5.new()
        md5_hash.update(bytes(msg, "utf-8"))
        return md5_hash.hexdigest()

    def AES_enc(self,msg):
        text = pad(msg)
        text_bytes = _string_to_bytes(text)
        split_lists = []
        aes = AES(bytes.fromhex(self.K))
        for i in range(0, len(text_bytes), 16):
            ciphertext = aes.encrypt(text_bytes[i:i+16])
            split_lists.append(ciphertext)
        list_cipher = []
        for i in split_lists:
          #print(i)
          cipher = _bytes_to_string(i)
          list_cipher.append(base64.b64encode(cipher.encode()).decode())
        #print(list_cipher)
        return list_cipher
  
        
    def AES_dec(self,msg,key):
        dec = []
        aes = AES(bytes.fromhex(key))
        for i in msg:
            cipher = base64.b64decode(i)
            cipher = _string_to_bytes(cipher.decode())
            dec+=aes.decrypt(cipher)
        string = _bytes_to_string(dec)
        string = unpad(string)
        #print(string)
        return string

    def sendMsg(self,user):
        file_names = os.listdir('cloud')
        for file_name in file_names:
            if "enc_msg_" + user.name in file_name:
                print("You have message from",user.name, end = '\n')
                print("You must read it before send message to",user.name, end = '\n')
                return
        #GET ENC RSA PUBLIC KEY OF THE RECIEVER
        with open('cloud/E_'+user.name+'.txt', 'r') as f:
            enc_key = f.read().split()
 
        msg = input("ENTER MESSAGE: ")
        #ENCRYPT MESSAGE WITH AES
        with open('cloud/enc_msg_'+self.name+'.txt', 'w') as f:
            list = self.AES_enc(msg)
            for i in list:
                f.write(str(i))
                if i != len(list)-1:
                        f.write(str(" "))
        #ENCRYPT OWN AES KEY WITH RSA PUBLIC KEY OF THE RECIEVER
        with open('cloud/dec_key_'+self.name+'.txt', 'w') as f:
            list = self.RSA_enc(self.K,int(enc_key[0]),int(enc_key[1]))
            for i in list:
                f.write(str(i))
                if i != len(list)-1:
                        f.write(str(" "))
        #HASH MD5 MSG TO GET SIGANTURE AND ENCRYPT IT WITH OWN RSA PRIVATE KEY
        signature = self.MD5_hash(msg)
        with open('cloud/enc_msg_'+self.name+'_signature.txt', 'w') as f:
            list = self.RSA_enc(signature,self.D,self.N)
            for i in list:
                f.write(str(i))
                if i != len(list)-1:
                        f.write(str(" "))

        print("SEND MESSAGE SUCCESS !!!")
    def readMsg(self,user):
        file_names = os.listdir('cloud')
        if "enc_msg_" + user.name+".txt" not in file_names:
            print("You don't have message from",user.name, end = '\n')
            return
        #get AES KEY FROM SENDER
        #try:
        with open('cloud/dec_key_'+user.name+'.txt', 'r') as f:
            list = f.read().split()
            aes_key_sender = "".join(self.RSA_dec(list,self.D,self.N))
            
        #decrypt MSG with AES KEY
        with open('cloud/enc_msg_'+user.name+'.txt', 'r') as f:
            enc_msg = f.read().split()
            msg = self.AES_dec(enc_msg,aes_key_sender)
        #Get SIGNATURE OF DEC MSG
        signature = self.MD5_hash(msg)
        
        #Read Signature ENC MSG
        with open('cloud/E_'+user.name+'.txt', 'r') as f:
            enc_key = f.read().split()
        with open('cloud/enc_msg_'+user.name+'_signature.txt', 'r') as f:
            list = f.read().split()
            enc_sig = "".join(self.RSA_dec(list,int(enc_key[0]),int(enc_key[1])))
            
        #CHECK VALID SIGNATURE
        if (enc_sig == signature):
            print(user.name ,": " , msg, end='\n' )
            for file_name in file_names:
                if "key" in file_name or "msg" in file_name:
                    os.remove('cloud/'+file_name)
        else:
            print("WARNING !!!! Message has been tampered !!!")
        #except:
        #        print("WARNING !!!! IMPORTANT FILES MISSING OR CORRUPTED !!!")
alice = Users("alice")
bob  =  Users("bob")

listUser = []
listUser.append(alice)
listUser.append(bob)

def chooseUser(listUser,user):
    list = []
    for i in listUser:
        if(i.name != user.name):
            list.append(i.name)
    print("This is list user: ", list,"\n" )
    choice = input("Choose name user: ")
    while choice not in list:
         os.system('clear')
         print("This is list user: ", list,"\n" )
         choice = input("Choose name user: ")
    for i in listUser:
        if(i.name == choice):
            return i


def login(user):
  while True:
    os.system('clear')
    print("Menu of " + user.name+ ": " )
    print("a. Send Message")
    print("b. Read Message")
    print("c. Return Menu")
    choice = input("Enter your choice: ")
    if choice == 'a':
        os.system('clear')
        user.sendMsg(chooseUser(listUser,user))
        os.system('pause')
        continue
    elif choice == 'b':
        os.system('clear')
        user.readMsg(chooseUser(listUser,user))
        os.system('pause')
        continue
    elif choice == 'c':
        return
    else:
        print("Invalid choice. Please try again.")

def main():
  while True:
    os.system('clear')
    print("Menu:")
    print("1. Login as Alice")
    print("2. Login as Bob")
    print("3. Exit")
    choice = input("Enter your choice: ")
    if choice == '1':
      login(alice)
    elif choice == '2':
      login(bob)
    elif choice == '3':
      break
    else:
      print("Invalid choice. Please try again.")

main()

