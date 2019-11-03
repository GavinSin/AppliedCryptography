#!/usr/bin/env python3
# source: exam_client.py
# ver. 1.2
# Date- Jun 2019
#  - import traceback to help trace print in debugging (if needed) 
# Author : Karl Kwan
# Date : May 2019
# Application: part of the sample progams for ST2504-ACG assignment 2.
# This program simulates a client of an examination paper repository solution.
# It provides four main operational features:
# 1. initialization of META info.
# 2. send in an examination payload to the server
#       A payload include: META info, examination paper , examination solution
# 3. retrival of an examination payload based on module code
# 4. retrival of a list of modules that are ready for retrival  
# This client program will be used by
# 1. Examiners (Who set the exam paper) for retrival of file list and upload the exam paper payload.
# 2. Soc Exam Repo Administrator / Backup Administrator(s) for retrival of file list and retrival of the exam paper payload.

import sys, traceback
sys.path.append("..") # Adds parent directory to python3 modules path
import socket
import os 
import readline
import pickle
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from exam_util_v1_2 import Payload, Con_header, Resp_header, Repolist, Exam_Helper, Digital_message

class Exam_client:
    HOST, PORT = "localhost", 9999
    def usage(argv):
        # A class method to display the program usage
        print(f"Usage: {argv[0]} "+" {-i | -L | -u | -r}")
        print("required optins:")
        print("-i : META INFO initalization at current directory")
        print("-L : List all payloads")
        print("-u : upload examination payload from current directory")
        print("-r : retrive examintion payload and save in current directory")
    
    def __init__(self):
        self.block_size = 1024
        self.timeout_in_seconds = Exam_Helper.timeout_in_seconds  # default socket timeout 
        self.my_input = Exam_Helper.my_input # link to external helper function
        self.repo_owner_id = "" # SOC Exam Repo Owner id
        self.server_ip, self.server_port = "localhost", "9999" # initialize with default value
        self.staff_id, self.mod_code, self.exam_fn, self.sol_fn = "","","",""
        #The first task is to check if META file exist
        #if not, must prompt for the META info.
        exists = os.path.isfile('META.info')
        self.password = input("enter your password ==>")
        
        
        if not exists:
            self.init_meta()
        else:
            # load in pre-defined meta info
            try:
                with open('META.info') as meta:
                    self.server_ip=meta.readline().strip()
                    self.server_port=meta.readline().strip()
                    self.repo_owner_id=meta.readline().strip()
                    self.staff_id=meta.readline().strip()
                    self.mod_code=meta.readline().strip()
                    if self.mod_code != None and len(self.mod_code) > 0:
                        self.exam_fn=meta.readline().strip()
                        self.sol_fn=meta.readline().strip()
                    meta.close()
            except:
                print("Corrupted Meta file, please initialize again")
                sys.exit(-1)
                
        # verify password of the private key
        try: 
            self.privatekey = RSA.import_key(open('./'+self.staff_id+'_privatekey.der','rb').read(),passphrase=self.password)
            print("Password is correct.")
        except ValueError:
            print("The password is incorrect.")
            sys.exit(-1)
        except:
            print("key not created yet")
            sys.exit(-1)

        #obtain server's public key
        self.server_publickey = RSA.import_key(open('../key ring/server_publickey.pem').read())
                
    def init_meta(self):
        # need create a new set of meta info and store it in the
        # current working folder, with the file name, "META.info"
        # Here we need to prompt and confirm the meta info from the user
        # interactively.
        # the required meta info includes:
        # - Exam Server addresses (ip and port)
        # - Exam Repo Owner ID
        # - user unique ID
        ### The following three are optional for the Exam Repo Administrator
        # - The module code of the particular examination payload
        # - The file name of the examination paper (in the current working directory (CWD))
        # - The file name fo the solution of the examination paper (in the CWD)
        #################################################################
        while True:
            print(f"Initialzation of META INFO file")
            self.server_ip=self.my_input("Server IP address =>",self.server_ip)
            if self.server_ip == None or len(self.server_ip) ==0:
                continue
            self.server_port=self.my_input("Server Port No. =>",self.server_port)
            if self.server_port == None or len(self.server_port) ==0:
                continue
            self.repo_owner_id=self.my_input("Exam Repo Owner ID =>",self.repo_owner_id)
            if self.repo_owner_id == None or len(self.repo_owner_id) ==0:
                continue
            self.staff_id=self.my_input("Staff ID =>",self.staff_id)
            if self.staff_id == None or len(self.staff_id) ==0:
                continue
            self.mod_code=self.my_input("Module Code =>",self.mod_code)
            if self.mod_code == None or len(self.mod_code) ==0:
                break # no need to ask for the file names.
            self.exam_fn=self.my_input("Examination paper file name =>",self.exam_fn)
            if not os.path.isfile(self.exam_fn):
                if self.soc_admin_id != self.staff_id:
                    # file name cannot be blank if the mod_code has been entered.
                    continue
            self.sol_fn=self.my_input("Solution file name =>",self.sol_fn)
            if os.path.isfile(self.sol_fn):
               break            # all input have been captured. Can exit the loop now.
        #reach here implies all input parameters are valid.
        # Assume that all input is correct.
        try:
            with open('META.info',"w") as mfh:
                print(f"{self.server_ip}",file=mfh)
                print(f"{self.server_port}",file=mfh)
                print(f"{self.repo_owner_id}",file=mfh)
                print(f"{self.staff_id}",file=mfh)
                if self.mod_code != None and len(self.mod_code) > 0:
                    print(f"{self.mod_code}",file=mfh)
                    print(f"{self.exam_fn}",file=mfh)
                    print(f"{self.sol_fn}",file=mfh)
                mfh.close() # not required, just for my good old habit
        except:
            print("System Error! Please check and re-initialize the server META INFO") 

    def list_repo(self):
        #request the server for a list of uploaded files
        #need to send in the staff_id
        #for normal staff, the list only contain their own files.
        #for exam admin, the list contains all the uploaded files.
        def show_repo(rpo):
            if rpo.status == 'ok':
                print(rpo.content)
            else:
                print("Sorry. Nothing to show")
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Connect to server and send data
                sock.connect((self.server_ip, int(self.server_port)))
                sock.settimeout(self.timeout_in_seconds)
                # 1. first prepare a Con_header object to specify the list_repo request.
                #    with the staff_id
                
                req_header = Con_header(self.staff_id,'L')
                
                # seal up the header with client signature
                header_bytes = pickle.dumps(req_header)
                retrieve_dm = Digital_message(header_bytes,self.privatekey)
                send_bytes=pickle.dumps(retrieve_dm)

                # send the digital message containing the header over to server
                Exam_Helper.block_send(sock,send_bytes,self.block_size)

                # now waiting for answer from the repo server

                # receive digital message from the server
                dm_server_bytes = Exam_Helper.block_recv(sock,0,self.block_size) # 0 denotes to expect unknown length of bytes
                if dm_server_bytes == None or len(dm_server_bytes) < 1:
                    raise RuntimeError("socket connection broken")
                
                # load digital message
                dm_server = pickle.loads(dm_server_bytes)
                if not type(dm_server) is Digital_message:
                    raise RuntimeError("The reply from server has corrupted.")
                else:
                    print("Reply from server is received.")
                    
                #verify signature of resp header from server
                if(not dm_server.verify_signature(self.server_publickey)):
                    raise RuntimeError("The signature from client is not valid.")
                else:
                    print("The server signature is valid.")

                # load the response header
                resp_bytes = dm_server.header
                resp_header = pickle.loads(resp_bytes)
                currenttime = datetime.datetime.now()
                #print(f"[{resp_header.resp_type}] {resp_header.payload_size}" )
                #print(f"{type(resp_header)}")
                if not type(resp_header) is Resp_header:
                    raise RuntimeError("Reply from server has corrupted.\nConversation ended.")
                
                #verify timestamp of resp header from server
                #if !((current time > timestamp )&&( difference in time < 2days))
                elif(not(resp_header.timestamp.__le__(currenttime) and (resp_header.timestamp.__rsub__(currenttime).days<2))): 
                    raise RuntimeError("The the digital message from server has expired.")

                #verify response
                elif resp_header.resp_type != 'ok':
                    print("Sorry. Your request is invalid and has been rejected by the server.")
                else:
                    p_len = resp_header.payload_size
                    
                    print(f"Got the ack. Next will be the actual payload stream {p_len}")
                    # send a positive 'ready to recevie' ack to the server
                    sock.sendall(b"ack")
                    
                    # now is to wait for the actual payload_bytes.
                    encrypted_pload_bytes = Exam_Helper.block_recv(sock,p_len,self.block_size)

                    # decrypt the payload
                    symmetrickey = PKCS1_OAEP.new(self.privatekey).decrypt(resp_header.key)
                    pload_bytes = Exam_Helper.decrypt(encrypted_pload_bytes,symmetrickey)                    
                    pload = pickle.loads(pload_bytes)
                    
                    if type(pload) is Repolist:
                        print("Payload has just arrived")

                        # check the hash of payload
                        hash_of_pload = SHA256.new(pload_bytes)
                        hexhash_of_pload = hash_of_pload.hexdigest()
                        if(hexhash_of_pload==resp_header.payload_hash):
                            print("The hash of payload is valid")
                            # Print the payload list
                            #assume the repo_bytes contains a Repolist object
                            show_repo(pload)
                            # all done.
                            print("Retrieved files successfully")
                        else:
                            raise RuntimeError("The hash of payload is invalid")
                    else:
                        print("Unexpected Error. List operation has been failed!!!")
            
        except socket.timeout as tmerr:
            print("Network connection timout and program exits")
        except Exception as e:
            print("System Error! Please check and re-initialize the server META INFO")
            print(e)
        
    def retrieve_payload(self):
        mod_code=input("Module Code =>") # prompt for the target module code.
        if mod_code == None or len(mod_code) ==0:
            print("Sorry. Invalid module code")
            return
        uploader_id=input("Uploader ID (optional) =>") # prompt for the uploader id.
        
        # now try to connect to server and retrieve the exam paper payload of the module
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Connect to server and send/recv data
                sock.connect((self.server_ip, int(self.server_port)))
                sock.settimeout(self.timeout_in_seconds)
                
                # 1. first send an retrival request to the server
                #create digital message
                
                req_header = Con_header(self.staff_id,'r')
                req_header.mod_code = mod_code # This is the code entered by the user at the prompt.
                req_header.uploader_id = uploader_id.strip() # An optional input from the user.

                # seal up the header with client signature
                header_bytes = pickle.dumps(req_header)
                retrieve_dm = Digital_message(header_bytes,self.privatekey)
                send_bytes=pickle.dumps(retrieve_dm)
                
                # send the digital message containing the header over to server
                Exam_Helper.block_send(sock,send_bytes,self.block_size)
                
                # now waiting for answer from the repo server

                # receive digital message from the server
                dm_server_bytes = Exam_Helper.block_recv(sock,0,self.block_size)# 0 denotes to expect unknown length of bytes
                if dm_server_bytes == None or len(dm_server_bytes) < 1:
                    raise RuntimeError("socket connection broken")
                
                # load digital message
                dm_server = pickle.loads(dm_server_bytes)
                if not type(dm_server) is Digital_message:
                    raise RuntimeError("The reply from server has corrupted.")
                else:
                    print("Reply from server is received.")

                    
                #verify signature of resp header from server
                if(not dm_server.verify_signature(self.server_publickey)):
                    raise RuntimeError("The signature from client is not valid.")
                else:
                    print("The server signature is valid.")

                # load the response header
                resp_bytes = dm_server.header
                resp_header = pickle.loads(resp_bytes)
                currenttime = datetime.datetime.now()
                #print(f"[{resp_header.resp_type}] {resp_header.payload_size}" )
                #print(f"{type(resp_header)}")
                if not type(resp_header) is Resp_header:
                    raise RuntimeError("Reply from server has corrupted.\nConversation ended.")
                
                #verify timestamp of resp header from server
                #if !((current time > timestamp )&&( difference in time < 2days))
                elif(not(resp_header.timestamp.__le__(currenttime) and (resp_header.timestamp.__rsub__(currenttime).days<2))): 
                    raise RuntimeError("The the digital message from server has expired.")

                #verify response
                elif resp_header.resp_type != 'ok':
                    print("Sorry. Your request is invalid and has been rejected by the server.")
                else:
                    p_len = resp_header.payload_size
                    print(f"Got the ack. Next will be the actual payload stream {p_len}")
                    # send a positive 'ready to recevie' ack to the server
                    sock.sendall(b"ack")
                    
                    # now is to wait for the actual payload_bytes.
                    encrypted_pload_bytes = Exam_Helper.block_recv(sock,p_len,self.block_size)

                    # decrypt the payload
                    symmetrickey = PKCS1_OAEP.new(self.privatekey).decrypt(resp_header.key)
                    pload_bytes = Exam_Helper.decrypt(encrypted_pload_bytes,symmetrickey)                    
                    pload = pickle.loads(pload_bytes)
                    
                    if type(pload) is Payload:
                        print("Payload has just arrived")
                        
                        # check the hash of payload
                        hash_of_pload = SHA256.new(pload_bytes)
                        hexhash_of_pload = hash_of_pload.hexdigest()
                        if(hexhash_of_pload==resp_header.payload_hash):
                            print("The hash of payload is valid")
                            #save the two files to the current folder
                            with open(pload.exam_fn,"wb") as outf1:
                                outf1.write(pload.exam_qns)
                                outf1.close()
                            with open(pload.sol_fn,"wb") as outf2:
                                outf2.write(pload.exam_sol)
                                outf2.close()
                            # all done.
                            print("Retrieved files successfully")
                        else:
                            raise RuntimeError("The hash of payload is invalid")

                        
                    else:
                        print("Retrieved files failed")
        except socket.timeout as tmerr:
            print("Network connection timout and program exits")
      #  except:
       #     print("System Error! Please check and re-initialize the server META INFO")
            
    def upload(self):
        if len(self.staff_id) == 0 or len(self.mod_code) == 0:
            print("Sorry, you have nothing to upload")
            return
        #prepare the payload according to the Meta info.
        pload = Payload()
        pload.staff_id = self.staff_id
        pload.mod_code = self.mod_code
        pload.exam_fn=self.exam_fn
        pload.sol_fn=self.sol_fn
        try:
            with open(self.exam_fn,"rb") as f1:
                pload.exam_qns = f1.read() # read in the entire file and store it in pload.exam_qns
            with open(self.sol_fn,"rb") as f2:
                pload.exam_sol = f2.read() # read in the entire file and store it in pload.exam_sol
            # now the pload is ready for sending out
            pload_bytes=pickle.dumps(pload)
            #print(f"size of payload = {len(pload_bytes)}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Connect to server and start send/recv data
                sock.connect((self.server_ip, int(self.server_port)))
                sock.settimeout(self.timeout_in_seconds)

                
                # 1,first send an upload request with the length of the payload.
                # prepare request heaer
                req_header = Con_header(self.staff_id,'u')
                req_header.mod_code=self.mod_code
                req_header.payload_size = len(pload_bytes)
                #create hash for the payload
                pload_hash=SHA256.new(pload_bytes)
                req_header.payload_hash=pload_hash.hexdigest()
                
                #create encrypted symmetric key
                symmetrickey = get_random_bytes(32) #32bytes=256bit
                req_header.key=PKCS1_OAEP.new(self.server_publickey).encrypt(symmetrickey)
                
                #convert request header to bytes and seal in digital message
                header_bytes = pickle.dumps(req_header)
                upload_dm = Digital_message(header_bytes,self.privatekey)
                send_bytes = pickle.dumps(upload_dm)

                #send the digital_message over 
                Exam_Helper.block_send(sock,send_bytes,self.block_size)

                # now waiting for a response from the repo server
                
                #receive the response header from server
                dm_server_bytes = Exam_Helper.block_recv(sock,0,self.block_size)# 0 denotes to expect unknown length of bytes
                if dm_server_bytes == None or len(dm_server_bytes) < 1:
                    raise RuntimeError("socket connection broken")

                # load and check the Digital message
                dm_server = pickle.loads(dm_server_bytes)
                if(not type(dm_server) is Digital_message):
                    raise RuntimeError("The reply from server has corrupted.")
                print("Reply from server is received.")

                #verify signature of resp header from server
                if(not dm_server.verify_signature(self.server_publickey)):
                    raise RuntimeError("The signature from client is not valid.")
                print("The server signature is valid.")
                
                # check resp content, ok then send the payload
                resp_header = pickle.loads(dm_server.header)
                if type(resp_header) is Resp_header and resp_header.resp_type=='ok':
                    
                    #verify timestamp of resp header from server
                    currenttime = datetime.datetime.now()
                    #if !((current time > timestamp )&&( difference in time < 2days))
                    if(not(resp_header.timestamp.__le__(currenttime) and (resp_header.timestamp.__rsub__(currenttime).days<2))): 
                        raise RuntimeError("The the digital message from server has expired.")

                
                    print("Got the ack.")
                    print(f"Principal Admin {resp_header.p_admin_id}")
                    for backup_admin in resp_header.others:
                        print(f"Backup Admin {backup_admin}")
                        
                    # encrypt the payload to ensure safe transmittion of the data
                    encrypted_pload_bytes=Exam_Helper.encrypt(pload_bytes,symmetrickey)                        

                    # now sending out the payload with pload encrypted
                    print("Now uploading the payload")
                    Exam_Helper.block_send(sock,encrypted_pload_bytes,self.block_size)

                    # Receive final acknowledgement  from the server and return
                    received = str(sock.recv(self.block_size), "utf-8")
                    print("Received: {}".format(received))		
                    return()
                
                else:
                    raise RuntimeError("Reply from server has corrupted.\nConversation ended.")

        except RuntimeError as re:
            print(re)
        except socket.timeout as tmerr:
            print("Network connection timout and program exits")
        except:
            print("System Error! Please check and re-initialize the server META INFO")            
            traceback.print_exc(file=sys.stdout)
            
if __name__ == "__main__":
    # determine the intended command by the command line argument
    if len(sys.argv) != 2:
        Exam_client.usage(sys.argv)
        sys.exit(-1)
    # now can proceed    
    c = Exam_client()
    if sys.argv[1] == "-i":
        c.init_meta()
        sys.exit(0) # terminate the program.
    # double check if the server_port is okay
    try:
        chk = int(c.server_port)
        if chk < 9000 or chk > 20000:
            print("Invalid Server Port number. Please check and re-initialize your meta info")
            sys.exit(-1)
    except:
        print("Invalid Server Port number. Please check and re-initialize your meta info")
        sys.exit(-1)
    if sys.argv[1] == '-u':
        #print("upload payload")
        c.upload()
    elif sys.argv[1] == '-r':
        #print("retrieve payload")
        c.retrieve_payload()
    elif sys.argv[1] == '-L':
        #print("List repository")
        c.list_repo()
    else:
        print("Invalid Command Line Option")
        Exam_client.usage(sys.argv)
        sys.exit(-1)
    
