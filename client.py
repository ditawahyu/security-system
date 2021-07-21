import socket
import select
import sys
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# if len(sys.argv) != 3:
#     print "Correct usage: script, IP address, port number"
#     exit()
IP_address = "192.168.100.250" #str(sys.argv[1])
Port = 7777 #int(sys.argv[2])
server.connect((IP_address, Port))
server.send(b"!Cl_0e") # Client: OK
serverpukey = b"p43K=" #public_key=
# server_public_key = RSA.generate(2048, Random.new().read)

while True:
    sockets_list = [sys.stdin, server]
    read_sockets,write_socket, error_socket = select.select(sockets_list, [], [])
    for socks in read_sockets:
        if socks == server:
            message = socks.recv(2048)
            if serverpukey in message:
                message = message.replace(serverpukey, b'')
                message = message.replace(b"\r\n", b'')
                # print (message)
                #Convert string to key
                server_public_key = RSA.importKey(message)
            else:
                print (message)
        else:
            message = sys.stdin.readline()
            cipher = PKCS1_OAEP.new(server_public_key)
            # encrypted = server_public_key.encrypt(message, 32)
            encrypted = cipher.encrypt(time.ctime() + " > " + message)
            server.send(b"!enc_m=" + encrypted) #encrypted_message
            sys.stdout.write("<You>" + time.ctime() + " > ")
            sys.stdout.write(message)
            sys.stdout.flush()
server.close()
