# Import socket module 
from AES_Cipher import encrypt ,generate_key,decrypt 
from utilties import read_from_file,generate_public_key,gamal_digital_signature_for_DH_public_key,sha1,verify_signatures,modinv,random_less_q,random_coprime_less_than,mod_pow
import socket	
import threading

#--------reading q and alpha-----------
q_DH,alpha_DH,q_gamal,alpha_gamal=read_from_file("data.txt")
#-----------generating public and private keys for DH-----------
private_key_DH= random_less_q(q_DH-1)#less than q-1
public_key_DH=generate_public_key(q_DH,alpha_DH,private_key_DH)
#-----------generating public and private keys for elgamal-----------
private_key_gamal=random_less_q(q_gamal-1) #less than q-1
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
        data = send_socket.recv(1024)
        # if not data:
        #     break
        print("Bob:", decrypt(data,key))

def main():

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Get the local machine name and port
    host = socket.gethostname()
    port = 6666

    # Connect to the server
    client_socket.connect((host, port)) 


    #-----------exchanging elgamal keys-----------
    public_other_gamal = int(client_socket.recv(1024).decode())
    client_socket.send(str(public_key_gamal).encode())
    # print(public_other_gamal)

    #-----------sending DH public key after signing by Elgamal digital signature-----------
    #q=19
    #q-1=18
    # K=13 #gcd(13,18)=1
     # print(type(m))
    # print(S1,S2)
    #----- recieving DH public key and verifying -----------
    S1_S2_combined = client_socket.recv(1024).decode()
    data_parts = S1_S2_combined.split(",")
    S1_other = int(data_parts[1])
    S2_other = int(data_parts[2])
    public_other_DH=int(data_parts[0])
    # print(S1_other,S2_other)
    m_other=sha1(public_other_DH)
    if(verify_signatures(alpha_gamal,m_other,q_gamal,public_other_gamal,S1_other,S2_other)==False):
        print('Invalid digital signature \n')
        client_socket.close()

    else:
        print("Valid Digital Signature.... Start Chatting \n")
        #sending
        M=public_key_DH
        m=sha1(M)
        K=random_coprime_less_than(q_gamal-1)   
        if (K is None):
            print("Invalid K.  In Valid Generating Digital Signature.")
            return
        K_inverse=modinv(K,q_gamal-1)
        S1,S2=gamal_digital_signature_for_DH_public_key(K,K_inverse,alpha_gamal,q_gamal,private_key_gamal,m)
        combined_data = str(public_key_DH)+','+str(S1) +',' + str(S2)  # Concatenate digital signature to messgae
        client_socket.send(combined_data.encode())

        #-----------generate 256-bit AES key-----------
        DH_shared_key=mod_pow(public_other_DH,private_key_DH,q_DH)
        key=generate_key(DH_shared_key)
        # print(key)

        #-----------Chatting-----------
        sender_thread = threading.Thread(target=send, args=(client_socket,key,))
        reciever_thread = threading.Thread(target=recieve, args=(client_socket,key,))

        sender_thread.start()
        reciever_thread.start()


if __name__ == '__main__':
  main()