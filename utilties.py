import math
import hashlib

def read_from_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return [int(line.rstrip()) for line in lines] #rstrip() method removes any trailing whitespace characters, 
                                                #including the newline (\n) in this case.

def generate_public_key (q,alpha,private_key):
    return pow(alpha,private_key) % q

def sha1(secret_key):
    h = hashlib.sha1(str(secret_key).encode('utf-8'))
    hex_digest = h.hexdigest()
    truncated_str = hex_digest[:8]  # Take the first 'num_chars' characters
    return int(truncated_str, 16) 
def gamal_digital_signature_for_DH_public_key(K,K_inverse,alpha_gamal,q_gamal,private_key_gamal,q,m):
    S1=pow(alpha_gamal,K) % q_gamal
    S2=K_inverse*(m-private_key_gamal*S1) % q-1
    return S1,S2    

def verify_signatures(alpha_DH,m,q,public_key_DH,S1,S2):
    print('hhhh')
    V1=pow(alpha_DH,m)%q
    print(V1)
    V2=pow(public_key_DH,S1)*pow(S1,S2) %q
    return V1==V2