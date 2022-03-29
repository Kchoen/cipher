from Crypto import Random
from Crypto.Cipher import AES,ChaCha20,ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
import Cryptodome.Cipher.PKCS1_OAEP as PKCS1_OAEP
from Crypto.Hash import SHA256,Poly1305,HMAC
import time
import matplotlib.pyplot as plt
import numpy as np
import timeit
global CP_key
global CP_nonce
global CP_header
global CHA_key
global CHA_nonce
global mode
global plain
global cipher
global decrypt
global AES_key
global AES_IV
global RSA_key
global RSA_n
global HMAC_key
global CBC_MAC_key
global CBC_MAC_IV
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
def init_text(n):
    global plain
    global cipher
    global decrypt
    plain = Random.get_random_bytes(n)
    cipher=None
    decrypt=None
def ShowText():
    global plain
    global cipher
    global decrypt
    print('plaintext：',plain[:16])
    print('cipher：',cipher[:16])
    print('decrypt：',decrypt[:16])
def create_random_file(n=4096*1024+1):
    plaintext = Random.get_random_bytes(n)
    f = open('plain','wb')
    f.write(plaintext)
    f.close()
def AES_Encrypt(mode,key,IV):
    global plain
    global cipher
    global decrypt
    padtext = pad(plain,16)
    if mode == 'CBC':
        obj = AES.new(key,AES.MODE_CBC,IV)
        cipher = obj.encrypt(padtext) 
    elif mode == 'OCB':
        nonce = IV[:15]
        obj = AES.new(key,AES.MODE_OCB,nonce)
        cipher = obj.encrypt(padtext) 
    elif mode == 'GCM':
        nonce = IV[:15]
        obj = AES.new(key,AES.MODE_GCM,nonce)
        cipher = obj.encrypt(padtext) 
    elif mode == 'CCM':
        nonce = IV[:11]
        obj = AES.new(key,AES.MODE_CCM,nonce)
        cipher = obj.encrypt(padtext) 
    else:
        print('Error: mode not exists!')
def AES_Decrypt(mode,key,IV):
    global plain
    global cipher
    global decrypt
    if mode == 'CBC':
        obj = AES.new(key,AES.MODE_CBC,IV)
        padtext = obj.decrypt(cipher)
        decrypt = unpad(padtext,16) 
        
    elif mode == 'OCB':
        nonce = IV[:15]
        obj = AES.new(key,AES.MODE_OCB,nonce)
        padtext = obj.decrypt(cipher)
        decrypt = unpad(padtext,16) 
        
    elif mode == 'GCM':
        nonce = IV[:15]
        obj = AES.new(key,AES.MODE_GCM,nonce)
        padtext = obj.decrypt(cipher)
        decrypt = unpad(padtext,16) 
        
    elif mode == 'CCM':
        nonce = IV[:11]
        obj = AES.new(key,AES.MODE_CCM,nonce)
        padtext = obj.decrypt(cipher)
        decrypt = unpad(padtext,16) 
        
    else:
        print('Error: mode not exists!')
def AES_task():
    global AES_key
    global AES_IV
    global mode_
    AES_Encrypt(mode_,AES_key,AES_IV)
def RSA_task():
    global plain
    global cipher
    global decrypt
    global RSA_key
    global RSA_n
    long_encrypt =b''
    if RSA_n == 1024:
        ci = PKCS1_OAEP.new(RSA_key)
        for i in range(0,len(plain),80):
            long_encrypt+=ci.encrypt(plain[i:i+80])
    else:
        ci = PKCS1_OAEP.new(RSA_key)
        for i in range(0,len(plain),200):
            long_encrypt+=ci.encrypt(plain[i:i+200])
def SHA_task():
    global plain
    global cipher
    global decrypt
    h = SHA256.new()
    h.update(plain)
    cipher = h.hexdigest()
def CHA_task():
    global plain
    global cipher
    global decrypt
    cipher = ChaCha20.new(key=CHA_key,nonce=CHA_nonce).encrypt(plain)
def POLY_task():
    global plain
    global cipher
    global decrypt
    global POLY_key
    mac = Poly1305.new(key = POLY_key,cipher=AES)
    mac.update(plain)
    cipher = mac.hexdigest()
def CHA_POLY1_task():
    global plain
    global cipher
    global decrypt
    print('plain:\n-------\n',plain[:16])
    print('-------\nChaCha20:\n-------')
    key = Random.get_random_bytes(32)
    nonce = Random.get_random_bytes(12)
    cipher = ChaCha20.new(key=key,nonce=nonce).encrypt(plain)
    print(cipher[:16])
    mac_key = Random.get_random_bytes(32)
    mac = Poly1305.new(key=mac_key,cipher=ChaCha20)
    mac_nonce = mac.nonce
    print('-------\ngenerate_tag:\n-------')
    mac_tag = mac.hexdigest()
    print(mac_tag)
    print('-------\ndecrypt_tag:\n-------')
    decrypt_tag = Poly1305.new(key=mac_key,nonce=mac_nonce,cipher=ChaCha20).hexdigest()
    print(decrypt_tag)
    decrypt = ChaCha20.new(key=key,nonce=nonce).decrypt(cipher)
    print('-------\ndecrypt:\n-------\n',decrypt[:16],'\n-------')
def CHA_POLY2_task():
    global plain
    global cipher
    global decrypt
    global CP_key
    global CP_nonce
    global CP_header
    cha_pol = ChaCha20_Poly1305.new(key=CP_key,nonce=CP_nonce)
    cha_pol.update(CP_header)
    cipher,tag = cha_pol.encrypt_and_digest(plain)
def hMAC_task():
    global plain
    global cipher
    global HMAC_key
    hmac = HMAC.new(HMAC_key,digestmod=SHA256)
    hmac.update(plain)
    cipher = hmac.hexdigest() 
def CBC_MAC_task():
    global plain
    global cipher
    global CBC_MAC_key
    global CBC_MAC_IV
    obj = AES.new(CBC_MAC_key,AES.MODE_CBC,CBC_MAC_IV)
    cipher = obj.encrypt(plain)
    tag = cipher[-1-16:-1]
    cipher = tag
def IV_task():
    global plain
    global cipher
    global decrypt
    init_text(3000)
    padtext = pad(plain,16)
    print('unknown key:\n-------')
    AES_key = Random.get_random_bytes(16)
    AES_IV = AES_key
    print(AES_key,'\n-------')
    obj = AES.new(AES_key,AES.MODE_CBC,AES_IV)
    cipher = obj.encrypt(padtext)
    obj = AES.new(AES_key,AES.MODE_CBC,AES_IV)
    C2 = cipher[:16]+b'\0'*16+cipher[:16]
    P2 = obj.decrypt(C2)
    get_IV = byte_xor(P2[0:16],P2[32:48])
    print('find_IV:\n-------\n',get_IV,'\n-------')
def AES_plot(text_length):
    global AES_IV
    global AES_key
    global mode_
    modes = ['CBC','OCB','GCM','CCM']
    colors = ['pink','red','black','brown']
    for j in range(len(modes)):
        mode_ = modes[j]
        AES_key = Random.get_random_bytes(32)
        AES_IV = Random.get_random_bytes(16)
        spend_time=[]
        for i in text_length:
            init_text(i)
            s = timeit.timeit(AES_task,number=1)
            spend_time.append(s)
        plt.plot(text_length,spend_time,'s-',color=colors[j],label = 'AES'+'-256-'+modes[j])
def RSA_plot(n,text_length):
    global RSA_key
    global RSA_n
    RSA_n = n
    RSA_key = RSA.generate(n)
    spend_time=[]
    for i in text_length:
        init_text(i)
        s = timeit.timeit(RSA_task,number=1)
        spend_time.append(s)
    plt.plot(text_length,spend_time,'s-',color='b',label='RSA')
def SHA_plot(text_length):
    spend_time=[]
    for i in text_length:
        init_text(i)
        s = timeit.timeit(SHA_task,number=1)
        spend_time.append(s)
    plt.plot(text_length,spend_time,'o-',color='y',label='SHA-256')
def CHA_plot(text_length):
    global CHA_key
    global CHA_nonce
    CHA_key = Random.get_random_bytes(32)
    CHA_nonce = Random.get_random_bytes(12)
    spend_time=[]
    for i in text_length:
        init_text(i)
        s = timeit.timeit(CHA_task,number=1)
        spend_time.append(s)
    plt.plot(text_length,spend_time,'s-',color='g',label='ChaCha20')
def POLY_plot(text_length):
    global POLY_key
    POLY_key = Random.get_random_bytes(32)
    spend_time=[]
    for i in text_length:
        init_text(i)
        s = timeit.timeit(POLY_task,number=1)
        spend_time.append(s)
    plt.plot(text_length,spend_time,'o-',color='cyan',label='Poly1305')
def CHA_POLY_PLOT(text_length):
    global CP_key
    global CP_nonce
    global CP_header
    CP_key = Random.get_random_bytes(32)
    CP_nonce = Random.get_random_bytes(12)
    CP_header = Random.get_random_bytes(16)
    spend_time=[]
    for i in text_length:
        init_text(i)
        s = timeit.timeit(CHA_POLY2_task,number=1)
        spend_time.append(s)
    plt.plot(text_length,spend_time,'o-',color='purple',label='Cha+Poly')
def HMAC_PLOT(text_length):
    global HMAC_key
    HMAC_key = Random.get_random_bytes(32)
    spend_time=[]
    for i in text_length:
        init_text(i)
        s = timeit.timeit(hMAC_task,number=1)
        spend_time.append(s)
    plt.plot(text_length,spend_time,'o-',color='orange',label='HMAC')
def CBC_MAC_PLOT(text_length):
    global CBC_MAC_key
    global CBC_MAC_IV
    CBC_MAC_key = Random.get_random_bytes(32)
    CBC_MAC_IV = Random.get_random_bytes(16)
    spend_time=[]
    for i in text_length:
        init_text(i)
        s = timeit.timeit(CBC_MAC_task,number=1)
        spend_time.append(s)
    plt.plot(text_length,spend_time,'o-',color='yellow',label='CBC_MAC')
if __name__ =='__main__':
    init_text(3000)
    IV_task()
    text_length = [0,48000,80000,112000,144000,176000,208000,240000,272000,304000]
    AES_plot(text_length)    
    SHA_plot(text_length)
    CHA_plot(text_length)
    POLY_plot(text_length)
    CHA_POLY_PLOT(text_length)
    #RSA_plot(2048,text_length)
    HMAC_PLOT(text_length)
    CBC_MAC_PLOT(text_length)
    plt.legend()
    plt.show()