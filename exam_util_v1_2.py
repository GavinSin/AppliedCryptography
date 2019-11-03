# common module for AY20192020 S1 .
# ST2504 - ACG assginment2 (sample code)
# source: exam_util.py
# ver. 1.2 (jun 2019)
#   - ensure  block_recv is using timeout to detect end of data stream.
#   -slow down the block_send speed to avoid TCP errors.
# Author: Karl Kwan
# Date: May 2019
import binascii
import os
import socket
import readline
import datetime
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from Cryptodome.Util.Padding import pad, unpad
from time import sleep
class Payload():
    # A data class to encapusule all the Examination Paper Repositroy payload
    def __init__(self):
        self.staff_id=''
        self.mod_code=''
        self.exam_fn=''
        self.sol_fn=''
        self.exam_qns = '' # contain the exam question paper in bytes 
        self.exam_sol =''  # contain the solution in bytes
class Con_header():
    # A data class to encapusule the connection request header
    # A client sends in its request using an object of Con_header
    def __init__(self,reqID='',reqT='L'):
        self.request_type=reqT    # List, Upload, or Retrieve
        self.requester_id=reqID    # the staff id of the requester
        self.mod_code=''        # optional field to specify the target module.
        self.uploader_id=''     # optional filed only required by the retrieve payload request
        self.payload_size=0     # optional field to specify the payload size.
        self.timestamp=datetime.datetime.now() #timestamp
        self.payload_hash=''    # optional field - hash of payload
        self.key=''             # optional field - encrypted symmetric key
	
class Resp_header():
    # A data class to encapusule the connection reponse header
    # The server sends its response to a client request using an object of Resp_header
    def __init__(self,respT='ok'):
        self.resp_type=respT    # 'ok','reject'
        self.p_admin_id=''   # optional field - contains the principal exam admin id   
        self.others = []     # optional field - contains a list of backup exam admin ids.
        self.payload_size=0  # optional field - contains the payload_size for a retrieve request.
        self.timestamp=datetime.datetime.now()	#timestamp
        self.payload_hash='' # optional field - hash of payload
        self.key=''	     # optional field - encrypted symmetric key

class Digital_message():
    # A data class to encapusule the header and signature
    def __init__(self,sendheader,privatekey):
        self.header=sendheader
        self.sig=self.signing(sendheader,privatekey)

    def signing(self,sendheader,privatekey):
	# sign the request header with signature of the client
        ##the hash obj contains header's sha value
        header_hash=SHA256.new(sendheader)
        signer=pkcs1_15.new(privatekey)
        #sign the request header
        return signer.sign(header_hash)    
	
    def verify_signature(self,publickey):
		#verify signature of header received
        hash_resp = SHA256.new(self.header)
        try:
            pkcs1_15.new(publickey).verify(hash_resp,self.sig)
            return True
        except (ValueError, TypeError):
            return False

class Repolist():
    # A data class to encapusule all the Examination Paper Repositroy payload
    def __init__(self):
        self.status="empty" # contains either 'ok' or 'empty' : default is 'empty'
        self.content="No uploaded file." # or contains the printable list of relevant payload entries

class Exam_Helper():
    # A helper class to provide common utility functions and constants
    timeout_in_seconds = 10.0
    block_size = 1024
    block_send_interval = 0.01 # adjust this figure to control the block send speed 0.01 = 10 milliseconds. 
    # higher interval implies longer delay between each sending.
    def my_input(prompt,defval=""):
        # A class function that help to improve input() (provided default value)
        def hook():
            readline.insert_text(defval)
            if os.name != "nt": # windows does not have redisplay() nor require to use redisplay()
                readline.redisplay()
        readline.set_pre_input_hook(hook)    
        ans=input(f"{prompt}")
        readline.set_pre_input_hook() # CLEAR THE preset 
        if (ans == None or len(ans) ==0):
            return ""
        return ans
    def block_send(sock,data_in_bytes,blk_size=1024):
        totalsent = 0
        need2send = len(data_in_bytes)
        # using block sending instead of sendall()
        while totalsent < need2send:
            sent = sock.send(data_in_bytes[totalsent:totalsent+blk_size])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent
            print(f"\rTotal sent: {totalsent}",end="")
            sleep(Exam_Helper.block_send_interval) # pause for 10 - 30 milliseconds, to avaoid sending too fast.
        print()
        
    def block_recv(sock,expected_len,blk_size=1024):
        # Generic block receive routine, the routine will continue receiving incoming bytes
        # from the given socket until the total no. of received bytes equals to expected_len.
        # or when the sock.rec() returns None.
        # When the expected_len parameter is 0, this routine will end after a 1 second timeout no incoming bytes 
        buffer=[]
        total_recv = 0
        orginal_timeout=sock.gettimeout()
        if expected_len == 0:
            sock.settimeout(1)
        while True:
            try:
                blk_data = sock.recv(blk_size)
                if blk_data == None:    # no more incoming data
                    break
                buffer.append(blk_data)
                total_recv=total_recv+len(blk_data)
                #print(f"received bytes:{total_recv}")
                print(f"\rreceived bytes:{total_recv}",end="")
                if len(blk_data) < blk_size:
                    break        # got the last block already
                if expected_len > 0 and total_recv >= expected_len:
                    break        # got the last block already
            except socket.timeout as tmerr:
                if expected_len > 0:
                    raise RuntimeError("socket connection broken")
        #print("block recv has been completed normally")
        print()
        #need to join all the data in the buffer array into one single bytes object
        received_bytes = b"".join(buffer)
        if expected_len == 0:
            sock.settimeout(orginal_timeout) # restore the timeout value
        return received_bytes

    def int_of_string(s):
        return int(binascii.hexlify(s), 16)

    def encrypt(pload_bytes,symmetrickey):
        iv = os.urandom(16)
        ctr = Counter.new(128, initial_value = Exam_Helper.int_of_string(iv))
        cipher = AES.new(symmetrickey, AES.MODE_CTR, counter=ctr)
        encrypted_bytes = cipher.encrypt(pad(pload_bytes,AES.block_size))
        return iv + encrypted_bytes

    def decrypt(encrypted_bytes,symmetrickey):
        iv = encrypted_bytes[:16]
        ctr = Counter.new(128, initial_value = Exam_Helper.int_of_string(iv))
        cipher = AES.new(symmetrickey, AES.MODE_CTR, counter=ctr)
        pload_bytes = unpad(cipher.decrypt(encrypted_bytes[16:]),AES.block_size)
        return pload_bytes

