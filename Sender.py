from AES_Cipher import encrypt ,generate_key,decrypt 
from utilties import read_from_file,generate_public_key,gamal_digital_signature_for_DH_public_key,verify_signatures,sha1
import socket
import threading
#--------reading q and alpha-----------
q_DH,alpha_DH,q_gamal,alpha_gamal=read_from_file("data.txt")
#-----------generating public and private keys for DH-----------
private_key_DH=20 #less than q-1
public_key_DH=generate_public_key(q_DH,alpha_DH,private_key_DH)
#-----------generating public and private keys for elgamal-----------
private_key_gamal=7 #less than q-1
public_key_gamal=generate_public_key(q_gamal,alpha_gamal,private_key_gamal)

# Function to handle client connections
def send(client_socket,key):
    while True:
        # Send a response to the client
        message = input("")
        client_socket.send(encrypt(message,key))

    # Close the connection with the client
    # client_socket.close()

def recieve(send_socket,key):
    while True:
        # Receive data from the client
        data = client_socket.recv(1024)
        # if not data:
        #     break
        print("Alice:", decrypt(data,key))


# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get the local machine name and port
host = socket.gethostname()
port = 6666

# Bind to the port
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(5)

print("Server listening on {}:{}".format(host, port))

# while True:
# Wait for a connection
client_socket, addr = server_socket.accept()
print("Got a connection from {}".format(addr))

#-----------exchanging elgamal keys-----------
client_socket.send(str(public_key_gamal).encode())
public_other_gamal = int(client_socket.recv(1024).decode())
# print(public_other_gamal)

#-----------sending DH public key after signing by Elgamal digital signature-----------
#q=19
#q-1=18
M=public_key_DH
m=sha1(M)
# print(type(m))
K=11 #gcd(11,18)=1
K_inverse=5
S1,S2=gamal_digital_signature_for_DH_public_key(K,K_inverse,alpha_gamal,q_gamal,private_key_gamal,m)
# print(S1,S2)
combined_data = str(public_key_DH)+','+str(S1) +',' + str(S2)  # Concatenate digital signature to messgae
client_socket.send(combined_data.encode())
#----- recieving DH public key and verifying -----------
S1_S2_combined = client_socket.recv(1024).decode()
data_parts = S1_S2_combined.split(",")
S1_other = int(data_parts[1])
S2_other = int(data_parts[2])
public_other_DH=int(data_parts[0])
# print(S1_other,S2_other)
m_other=sha1(public_other_DH)
if(verify_signatures(alpha_gamal,m_other,19,public_other_gamal,S1_other,S2_other)==False):
    print('Invalid digital signature \n')
    client_socket.close()
else:
    print("Valid Digital Signature.... Start Chatting \n")

    #-----------generate 256-bit AES key-----------
    DH_shared_key=pow(public_other_DH,private_key_DH)%23
    key=generate_key(DH_shared_key)
    # print(key)
    
    #-----------Chatting-----------
    sender_thread = threading.Thread(target=send, args=(client_socket,key,))
    reciever_thread = threading.Thread(target=recieve, args=(client_socket,key,))

    sender_thread.start()
    reciever_thread.start()
