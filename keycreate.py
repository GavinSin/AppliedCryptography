import sys
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15

class Key_Create:

    def usage(argv):
        # A class method to display the program usage
        print(f"Usage: {argv[0]} "+" { -g | -c }")
        print("required optins:")
        print("-g : generate a key pair for a staff\n\t public key will generate at the 'key ring' folder\n\t privatekey will generate at this folder (remember to move it to his own folder)")
        print("-c : change password for a staff\n\t the privatekey must be in the same folder as this program.\n\t the public key must be in the 'key ring' folder")

    def generate_new_key(self):
        print("A Simple Program for key pair export and import operations")
        self.staffid = input("Type in a staff id please =>")
        self.secret_phrase = input("Type in a pass phrase please =>")
        print("Generating an RSA key pair...")
        self.rsakey_pair=RSA.generate(2048)  
        print("Done generating the key pair.")
        self.generate()

    def change_passwd(self):
        print("A Simple Program to change the password of the staff")
        self.staffid = input("Type in the staff id please =>")
        passwd = input("Type in the pass phrase please =>")
        
        try:
            key_bytes=open("./"+self.staffid + "_privatekey.der","rb").read()
            self.rsakey_pair=RSA.import_key(key_bytes,passphrase=passwd)
            print("Import private key has been completed")
            self.secret_phrase = input("Type in the new pass phrase please =>")

        except ValueError:
            print('Opps! Wrong password.')
            sys.exit(-1)
        except:
            print("Opps! Private key not found.")
            sys.exit(-1)
        self.generate()

    def generate(self):
        print("export the keypair to 'privatekey.der' with AES encryption in binary format")
        prikey_in_der=self.rsakey_pair.export_key(format="DER", passphrase=self.secret_phrase, pkcs=8,protection="scryptAndAES128-CBC")
        try:
            open("./"+self.staffid +"_privatekey.der","wb").write(prikey_in_der)
            print("Export private key has been completed")
        except:
            print("Opps! failed to export the private key.")
            sys.exit(-1)
        pubkey_in_pem=self.rsakey_pair.publickey().exportKey()
        print("export the public key to 'staffid_publickey.der' with Base64 format")
        try:
            open("./key ring/"+self.staffid + "_publickey.pem","wb").write(pubkey_in_pem)
            print("Export public key has been completed")
        except:
            print("Opps! failed to export the public key")
            sys.exit(-1)

        # now try to import back the key pair (the private key)
        print("now try to import back the key pair (the private key)")
        prikey_bytes=open("./"+self.staffid + "_privatekey.der","rb").read()
        restored_keypair=RSA.import_key(prikey_bytes,passphrase=self.secret_phrase)
        if restored_keypair == self.rsakey_pair:
            print("Restored the key pair successfully")
        pubkey_bytes=open("./key ring/"+self.staffid + "_publickey.pem","r").read()
        restored_pubkey=RSA.import_key(pubkey_bytes)
        if restored_pubkey == self.rsakey_pair.publickey():
            print("Restored the public key successfully")   

        #now try to verify signature
        print("now try to verify its signature")
        message="this is a message going to be signed"
        h=SHA256.new(message.encode())
        signer=pkcs1_15.new(self.rsakey_pair)
        signature=signer.sign(h)
        verifier = pkcs1_15.new(self.rsakey_pair.publickey())
        try:
                verifier.verify(h,signature)
                print("the signature is valid")
        except:
                print("the signature is not valid")

if __name__=="__main__":
    # determine the intended command by the command line argument
    if len(sys.argv) != 2:
        Key_Create.usage(sys.argv)
        sys.exit(-1)
    #now can start creating key
    k=Key_Create()
    if sys.argv[1] == '-g':
        k.generate_new_key()
    elif sys.argv[1] == '-c':
        k.change_passwd()
    else:
        print("Invalid Command Line Option")
        sys.exit(-1)
