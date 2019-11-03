#!/usr/bin/env python3
# source: exam_server.py
# ver. 1.2.
#   Date: Jun 2019
#   - import traceback to help trace print in debugging (if needed) 
# A multithreaded Stream Socket Server program based on
# socketserver Framework
# ref: https://docs.python.org/3/library/socketserver.html
# Author : Karl Kwan
# Date : May 2019
# Application: part of the sample progams for ST2504-ACG assignment 2.
# This exam_server.py (repo server) should only be started by the repo_owner
import sys, traceback 
sys.path.append("..") # Adds parent directory to python3 modules path
import os , re , time
import socket
import socketserver
import pickle
import datetime
import logging
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from exam_util_v1_2 import Payload, Con_header, Resp_header, Repolist, Exam_Helper, Digital_message
#This is to create a log file called "acg.log" in the server directory and format how the actions will be displayed in the log file
LOG_FORMAT = "%(asctime)s - %(funcName)s - %(message)s"
logging.basicConfig(filename = "acg.log", level = logging.CRITICAL, format = LOG_FORMAT, filemode = "a")
logger = logging.getLogger()

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    def setup(self):
        # this will be invoked once at the beginnig of the instantiation.
        #print("setup is invoked")
        self.buffer_size=Exam_Helper.block_size
        self.meta = Security_Check_Point()
        self.privatekey = RSA.import_key(open('./server_privatekey.der','rb').read(),passphrase='server')

    def get_payload(self,req_header):
        print(f"entering get_payload of {req_header.mod_code}, uploaded by : {req_header.uploader_id}")
        scp=self.meta
        files = [f for f in os.listdir('.') if os.path.isfile(f) and \
                 f.endswith(req_header.uploader_id+'.dat') and f.startswith(req_header.mod_code)]
        #print(files)
        if len(files) != 1 :
            return None
        
        try:
            with open(files[0],"rb") as f1:
                payload_bytes = f1.read() # read in the entire file and store it in payload_bytes
                f1.close()
            return payload_bytes
        except:
            print(f"Serious FILE I/O error. Cannot open/read from {files[0]}")
            return None
        
    def send_payload(self,pload_bytes):
        try:
            # now waiting for ready to receive signal from the client 
            ack = str(self.request.recv(self.buffer_size), "utf-8")
            if ack != "ack":
                print("client abort")
                return
            print("Got the ack. Send the payload now")
            Exam_Helper.block_send(self.request,pload_bytes,self.buffer_size)
        except socket.timeout as tmerr:
            print("handler timout and exits")
            
    def get_pload_list(self,staff_id):
        #print(f"in get_pload_list staff_id is {staff_id}")
        def get_Playload_Info(fname,staff_id):
            # get_Playload_Info is a sub function of get_pload_list()
            # Playload Info includes the module code, the examiner id and the upload date/time
            scp=self.meta
            output=""
            id=re.search(r"\.([^\.]*)",fname) # search for staff_id from the filename.
            if id and id.lastindex == 1:
                if staff_id == scp.p_admin_id or staff_id in scp.others or staff_id == id.group(1):
                    # retrieve all the files for admin or user own files.
                    mod_code=re.search(r"^[^\.]*",fname)
                    if mod_code:
                        t=os.stat(fname).st_mtime
                        output=f"{mod_code.group(0):20} {id.group(0)[1:]:10} {time.ctime(t):30}\n"
            return output
            
        result=""
        files = [f for f in os.listdir('.') if os.path.isfile(f) and f.endswith('.dat')]
        #print(files) # all the matched files.
        for f in files:
            result=result+get_Playload_Info(f,staff_id)
        repo=Repolist() # create a default (and empty) Repolist object.
        if len(result) > 0:
            repo.status="ok"
            repo.content=f"{'Module_Code':20} {'Upload_By':10} {'Last_Modified':30}\n"+result
        return pickle.dumps(repo)
    
   
            
    def handle_upload(self,req_header):
        logging.critical(f"{req_header.requester_id} request to upload payload of {req_header.mod_code} to server.")
        try:
            p_len = req_header.payload_size
            # print(f"payload size: {p_len}") # for debugging.
            # send a positive ack to the client
            scp=self.meta       # Retrieve the server owner, exam admid ids.

            # prepare response header
            resp_header= Resp_header()
            resp_header.resp_type='ok'

            # The following responses may provide the info for the client to encrypt the
            # payload in such a way that, all the exam admins can decrypt the payload at their ends.
            resp_header.p_admin_id=scp.p_admin_id  
            resp_header.others = scp.others
            			
	    # prepare server digital message with server signature
            header_bytes = pickle.dumps(resp_header)
            response_dm = Digital_message(header_bytes,self.privatekey)
            send_bytes = pickle.dumps(response_dm)

	    # send the digital_message over
            Exam_Helper.block_send(self.request,send_bytes,self.buffer_size)
	    

            # now is waiting for the payload from the client.
            encrypted_pload_bytes = Exam_Helper.block_recv(self.request,p_len,self.buffer_size).strip()
            symmetrickey=PKCS1_OAEP.new(self.privatekey).decrypt(req_header.key)
            pload_bytes = Exam_Helper.decrypt(encrypted_pload_bytes,symmetrickey)
            pload = pickle.loads(pload_bytes)
            
            if type(pload) is Payload:
                print("Payload has just arrived")
                
                #verify the hash of decrypted payload
                hash_of_pload = SHA256.new(pload_bytes)
                hexhash_of_pload = hash_of_pload.hexdigest()
                if(hexhash_of_pload==req_header.payload_hash):
                    print("The hash of payload is valid")
                else:
                    logging.critical(f"{req_header.requester_id} has uploaded files that does not match the hash, aborted!")
                    raise RuntimeError("The hash of payload is invalid")
                    
                print(f"staff id : {pload.staff_id}")
                print(f"module code : {pload.mod_code}")
                print(f"Exam paper file name: {pload.exam_fn}")
                print(f"Exam solution file name : {pload.sol_fn}")
                
                # now write payload bytes to a binary file.
                with open(pload.mod_code+'.'+pload.staff_id+".dat","wb") as outf:
                    outf.write(pload_bytes)
                # send back an acknowledgement message to the client
                self.request.sendall(b"upload operation has been completed successfully")
                print(f"{req_header.requester_id} has uploaded files into server successfully!")
                logging.critical(f"{req_header.requester_id} has uploaded files into server successfully!")
            else:
                #print(f"pload object type => {type(pload)}")
                # send back an error message to the client
                self.request.sendall(b"upload operation has been failed!!!")
                logging.critical(f"{req_header.requester_id} has uploaded files into server unsuccessfully!")
        except socket.timeout as tmerr:
            print("handler timout and exits")
            logging.critical(f"{req_header.requester_id} has uploaded files into server unsuccessfully due to time out")
            pass
        except:
            print(f"handler exists due to unexpected error : {sys.exc_info()[0]}")
            logging.critical(f"{req_header.requester_id} has uploaded files into server unsuccessfully due to {sys.exc_info()[0]}")
            traceback.print_exc(file=sys.stdout)
  
    def handle_retrieval(self,req_header,client_publickey):
        logging.critical(f"{req_header.requester_id} request to retrieve payload of {req_header.mod_code} from server")
        print(f"{req_header.requester_id} is requesting to retrieve the payload of {req_header.mod_code}")
        scp=self.meta
        resp_header= Resp_header()
        if req_header.requester_id == scp.p_admin_id or req_header.requester_id in scp.others:
            payload_bytes=self.get_payload(req_header)
            # check requested file exist
            if payload_bytes != None:
                resp_header.resp_type='ok'
                resp_header.payload_size=len(payload_bytes)
                
                # create hash for payload
                hash_of_pload = SHA256.new(payload_bytes)
                resp_header.payload_hash = hash_of_pload.hexdigest()
                
                #create encrypted symmetric key
                symmetrickey = get_random_bytes(32) #32bytes=256bit
                resp_header.key=PKCS1_OAEP.new(client_publickey).encrypt(symmetrickey)
                
                #convert response header to bytes and seal in digital message
                header_bytes = pickle.dumps(resp_header)
                response_dm = Digital_message(header_bytes,self.privatekey)
                resp_bytes = pickle.dumps(response_dm)

                #send the digital_message over
                print("sending resp_header to client")
                Exam_Helper.block_send(self.request,resp_bytes,self.buffer_size)
                logging.critical(f"{req_header.requester_id} received accept header")

                #encrypt the payload for safe transmittion
                encrypted_payload_bytes = Exam_Helper.encrypt(payload_bytes,symmetrickey)
                self.send_payload(encrypted_payload_bytes)
                logging.critical(f"{req_header.requester_id} retrieved payload")
                return
            
        resp_header.resp_type='rejected'
        logging.critical(f"{req_header.requester_id} is rejected.")
        header_bytes=pickle.dumps(resp_header)
        response_dm = Digital_message(header_bytes,self.privatekey)
        resp_bytes = pickle.dumps(response_dm)
        print("sending rejected resp_header to client")
        Exam_Helper.block_send(self.request,resp_bytes,self.buffer_size)
        print("rejected resp_header to client sent")
        logging.critical(f"{req_header.requester_id} received rejected header")

    def handle_get_payload_listing(self,req_header,client_publickey):
        logging.critical(f"{req_header.requester_id} is requesting to retrieve his listing")
        scp=self.meta
        resp_header= Resp_header()
        staff_id = req_header.requester_id

        try:
            # repo_bytes is from a Repolist object.
            rpo_bytes=self.get_pload_list(staff_id)
            
            # start copy
            # check requested file exist
            if rpo_bytes != None:
                resp_header.resp_type='ok'
                resp_header.payload_size=len(rpo_bytes)
                
                # create hash for payload
                hash_of_rpo = SHA256.new(rpo_bytes)
                resp_header.payload_hash = hash_of_rpo.hexdigest()
                
                #create encrypted symmetric key
                symmetrickey = get_random_bytes(32) #32bytes=256bit
                resp_header.key=PKCS1_OAEP.new(client_publickey).encrypt(symmetrickey)
                
                #convert response header to bytes and seal in digital message
                header_bytes = pickle.dumps(resp_header)
                response_dm = Digital_message(header_bytes,self.privatekey)
                # print("From server" + str(type(response_dm)))
                resp_bytes = pickle.dumps(response_dm)

                #send the digital_message over
                print("sending resp_header to client")
                Exam_Helper.block_send(self.request,resp_bytes,self.buffer_size)
                logging.critical(f"{req_header.requester_id} received accept header")

                #encrypt the payload for safe transmittion
                encrypted_payload_bytes = Exam_Helper.encrypt(rpo_bytes,symmetrickey)
                self.send_payload(encrypted_payload_bytes)
                logging.critical(f"{req_header.requester_id} retrieved list")
                return

            resp_header.resp_type='rejected'
            logging.critical(f"{req_header.requester_id} is rejected.")
            header_bytes=pickle.dumps(resp_header)
            response_dm = Digital_message(header_bytes,self.privatekey)
            resp_bytes = pickle.dumps(response_dm)
            print("sending rejected resp_header to client")
            Exam_Helper.block_send(self.request,resp_bytes,self.buffer_size)
            print("rejected resp_header to client sent")
            logging.critical(f"{req_header.requester_id} received rejected header")
            # end copy
        
        except socket.timeout as tmerr:
            print("handler timout and exits")
            logging.critical(f"{req_header.requester_id} has uploaded files into server unsuccessfully due to time out")
        except:
            print(f"handler exists due to unexpected error : {sys.exc_info()[0]}")
            logging.critical(f"{req_header.requester_id} has uploaded files into server unsuccessfully due to {sys.exc_info()[0]}")
        
    
    def handle(self):
        # self.request is the TCP socket connected to the client
        # Set a timeout value on this socket connection, to avoid
        # this server to be held up by a malfunction client.  
        self.request.settimeout(Exam_Helper.timeout_in_seconds)
        #try:
        print(f"Connection from {self.client_address[0]}:{self.client_address[1]}")

        #receive digital message from client
        self.data = self.request.recv(self.buffer_size).strip()
        if self.data == None:
            print(f"Received a null content from {self.client_address[0]}:{self.client_address[1]}")
            logging.critical(f"Received a null content from {self.client_address[0]}:{self.client_address[1]}")
            return() 
        # self.data should contain a valid Digital_message object
        dm_client = pickle.loads(self.data)
        if(type(dm_client) is not Digital_message):
            print(f"Received an invalid content from {self.client_address[0]}:{self.client_address[1]}")
            logging.critical(f"Received an invalid content from {self.client_address[0]}:{self.client_address[1]}")
            return()

        req_header = pickle.loads(dm_client.header)            

        # verify if it is a connection header
        if type(req_header) is Con_header and req_header.request_type in ['u','r','L']:
            #verify timestamp, if expired
            client_timestamp = req_header.timestamp
            currenttime = datetime.datetime.now()
            #if !((current time > timestamp )&&( difference in time < 2days))
            if(not(client_timestamp.__le__(currenttime) and (client_timestamp.__rsub__(currenttime).days<2))): 
                print("The the digital message has expired.")
                logging.critical(f"Received an expired content from {self.client_address[0]}:{self.client_address[1]}. Timestamp:{client_timestamp}")
                return()
            else:
                # verify the signature of the client
                try:
                    client_publickey = RSA.import_key(open('../key ring/'+req_header.requester_id+'_publickey.pem').read())
                except:
                    print(f"The client {req_header.requester_id}'s public key does not exist.")
                    logging.critical("The client {req_header.requester_id} from {self.client_address[0]}:{self.client_address[1]} tries to connect but public key does not exist.")
                    return()
                                     
                hash_req = SHA256.new(dm_client.header)
                try:
                    pkcs1_15.new(client_publickey).verify(hash_req, dm_client.sig)
                    print(f"The {req_header.requester_id} signature is valid.")
                except (ValueError, TypeError):
                    print("The signature from client is not valid.")
                    logging.critical(f"The signature from {req_header.requester_id} at {self.client_address[0]}:{self.client_address[1]} is not valid.")
                    return()

                #divide the functions 
                if req_header.request_type=='u':
                    self.handle_upload(req_header)
                elif req_header.request_type =='r':
                    self.handle_retrieval(req_header,client_publickey)
                else: # must be 'L'
                    self.handle_get_payload_listing(req_header,client_publickey)
        else:
            #invalid request
            print(f"Handler exits due to invalid request: {req}")
            logging.critical(f"The client {req_header.requester_id} from {self.client_address[0]}:{self.client_address[1]} tries an sinvalid request: {req}.")
            return()
                
##        except socket.timeout as tmerr:
##            print("handler timout and exits")
##        except:
##            print(f"handler exits due to unexpected error : {sys.exc_info()[0]}")
 
    def finish(self):
        print("reaching finish() of the handler")
        return socketserver.BaseRequestHandler.finish(self)

class Security_Check_Point():
    def __init__(self):
        self.my_input = Exam_Helper.my_input  # function mapping
        self.server_port="9999"
        self.repo_owner_id=""    # Clients only trust the server started by this repo_owner.
        self.p_admin_id = ""     # principal Exam Admin, whom can retrieve and decrypt the payload
        self.others = []         # other/backup Exam admin, whom can retrieve and decrypt the payload
        #Check if Host_META file exist
        #if it exists, load in the Host META info.
        exists = os.path.isfile('Host_META.info')
        if exists:
            # load in pre-defined meta info
            try:
                tmp_list=[]
                with open('./Host_META.info') as meta:
                    for line in meta:
                        tmp_list.append(line.strip())
                    meta.close()
                if len(tmp_list) < 3:  # minimum should have port number, owner id and p_admin_id
                    print("Corrupted Host_Meta file, please initialize again")
                    sys.exit(-1)
                self.server_port=tmp_list[0]
                self.repo_owner_id=tmp_list[1]
                self.p_admin_id=tmp_list[2]
                self.others=tmp_list[3:] # The rest, if any, goes to the others
            except:
                print("Corrupted Host_Meta file, please initialize again")
                sys.exit(-1)
                
    def authenticate(self):
        # verify password of the private key
        password = input('Enter your password for the server (required) =>')
        try: 
            RSA.import_key(open('./'+self.repo_owner_id+'_privatekey.der','rb').read(),passphrase=password)
            print("Password is correct.")
        except ValueError:
            print("The password is incorrect.")
            return False
        except:
            print("Staff key not created yet")
            return False
        return True
    
    def start_up(self):
        # 
        # Prompt and user to confirm the repo_owner_id
        # Prompt the user to confirm the p_admin_id
        while True:
            self.server_port=self.my_input("Server Port No. (9000-20000) =>",self.server_port)
            if self.server_port == None or len(self.server_port) ==0:
                continue
            try:
                port_num=int(self.server_port)
                if not port_num in range(9000,20001):
                    continue
            except:
                continue
            self.repo_owner_id=self.my_input("Repo owner ID =>",self.repo_owner_id)
            if self.repo_owner_id == None or len(self.repo_owner_id) == 0:
                continue
            self.p_admin_id=self.my_input("Principal Exam Repo Administrator ID =>",self.p_admin_id)
            if self.p_admin_id != None and len(self.p_admin_id) > 0:
                break
        # now checking if the repo owner ID is confirmed.
        if not self.authenticate():
            print("Exam Repo Owner Authentication Failed. Program is aborted!")
            sys.exit(-1)
            
        print("Review and Update the Backup Administrator list")
        new_others=[]
        for bkup in self.others:
            new_id=self.my_input(f"Backup Administrator ID {len(new_others)+1}=>",bkup)
            if new_id != None and len(new_id.strip())>0:
                new_others.append(new_id.strip())
        while True:
            new_id=self.my_input(f"Backup Administrator ID {len(new_others)+1} => ","")
            if new_id != None and len(new_id.strip())>0:
                new_others.append(new_id.strip())
            else:
                break
        # now everything is confirmed. Time to update the Host_META.info
        with open('Host_META.info','w') as meta:
            print(self.server_port,file=meta)
            print(self.repo_owner_id,file=meta)
            print(self.p_admin_id,file=meta)
            for other in new_others:
                print(other,file=meta)   
            meta.close()
if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 9999  # this ensure the server is listening on all available network interfaces.
    # Security_Check_Point Object:
    # It is responsible for the Server 'start up checking' and to maintain of a set of Server Meta data
    # The server start up checking procedure can only be carried out by the 'Repository Owner'
    # The Security_Check_Point object will authenticate user before starting up the server.
    # If an unauthorized user tries to start the server, yes, he can, but all the incoming clients shall abort
    # the communication.
    # Server Meta is kept in the file 'Host_Meta.info'
    # It contains the Repo Owner ID, Principal Exam Administrator ID.
    # and a few extra backup Exam Administrator IDs.
    # All Exam Administrators (Principal and backup) are allowed to download 'any' Exam Payloads.

    scp = Security_Check_Point()
    scp.start_up()
    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, int(scp.server_port)), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        print("Starting Exam server now, interrupt the program with Ctrl-C")
        server.serve_forever()
