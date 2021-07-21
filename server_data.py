import socket
import select
import sys
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from _thread import *


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
"""
the first argument AF_INET is the address domain of the socket. This is used when we have an Internet Domain
with any two hosts
The second argument is the type of socket. SOCK_STREAM means that data or characters are read in a continuous flow
"""
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#if len(sys.argv) != 3:
 #   print ("Correct usage: script, IP address, port number")
  #  exit()
IP_address = "192.168.100.67"
#IP_address = str(sys.argv[1])
#Port = int(sys.argv[2])
Port = 50002

random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()
encrypt_str = b"!enc_m="  #encrypted_message

server.bind((IP_address, Port)) 
#binds the server to an entered IP address and at the specified port number. The client must be aware of these parameters
server.listen(100)
#listens for 100 active connections. This number can be increased as per convenience
list_of_clients=[]

def clientthread(conn, addr):
    conn.send(b"Wt2c_R \n") #welcome to this chat room
    #sends a message to the client whose user object is conn
    while True:
            try:     
                message = conn.recv(2048) 
                message = message.replace(b"\r\n", b'')  
                if message:
                    if message == b"!Cl_0e":  #Client: OK
                        message_to_send = b"p43K=" + public_key.exportKey() + b"\n"  #public_key=
                        #print (message_to_send)
                        conn.send (message_to_send)
                        #broadcast(message_to_send,conn)
                    elif encrypt_str in message: #Reveive encrypted message and decrypt it.
                        message = message.replace(encrypt_str, b'')
                        #print ("Received:\nEncrypted message = " +str(data))
                        #encrypted = eval(data)
                        encrypted = message
                        cipher = PKCS1_OAEP.new(private_key)

                        tmp_message = message
                        signer = PKCS1_v1_5.new(private_key)
                        digest = SHA.new()
                        digest.update(tmp_message)
                        signature = signer.sign(digest)
                        pub_signer = PKCS1_v1_5.new(public_key)
                        pub_digest = SHA.new()
                        pub_digest.update(tmp_message)
                        verify = pub_signer.verify(pub_digest, signature)
                        #print (verify)
                        if verify == True:
                            decrypted = cipher.decrypt(encrypted)
                            #print (decrypted.decode("utf-8"))
                            print ("<" + addr[0] + "> " + decrypted.decode("utf-8"))
                            #message_to_send = "<" + addr[0] + "> " + message
                            #broadcast(message_to_send,conn)
                    #prints the message and address of the user who just sent the message on the server terminal
                else:
                    remove(conn)
            except:
                continue

def broadcast(message,connection):
    for clients in list_of_clients:
        if clients!=connection:
            try:
                clients.send(message)
            except:
                clients.close()
                remove(clients)

def remove(connection):
    if connection in list_of_clients:
        list_of_clients.remove(connection)

while True:
    conn, addr = server.accept()
    """
    Accepts a connection request and stores two parameters, conn which is a socket object for that user, and addr which contains
    the IP address of the client that just connected
    """
    list_of_clients.append(conn)
    print (addr[0] + " connected") #connected
    #maintains a list of clients for ease of broadcasting a message to all available people in the chatroom
    #Prints the address of the person who just connected
    start_new_thread(clientthread,(conn,addr))
    #creates and individual thread for every user that connects

conn.close()
server.close()