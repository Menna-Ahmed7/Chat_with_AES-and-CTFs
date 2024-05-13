import math
import hashlib
import random
from math import gcd

def read_from_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return [int(line.rstrip()) for line in lines] #rstrip() method removes any trailing whitespace characters, 
                                                #including the newline (\n) in this case.
def modinv(k, q):
    g, x, y = extended_euclidean_algorithm(k, q)
    if g != 1:
        return None  # modular inverse does not exist
    else:
        return x % q

def extended_euclidean_algorithm(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = divmod(b, a)
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y

def generate_public_key (q,alpha,private_key):
    # pow(alpha,private_key) % q
    return mod_pow(alpha,private_key,q)

def mod_pow(a, b, n):
    result = 1
    while b > 0:
        # Check if the least significant bit of b is 1
        if b & 1:
          result = (result * a) % n
        # Right shift b by 1 to move to the next bit
        b >>= 1
        a = (a * a) % n
    return result

def sha1(secret_key):
    h = hashlib.sha1(str(secret_key).encode('utf-8'))
    hex_digest = h.hexdigest()
    # truncated_str = hex_digest[:8]  # Take the first 'num_chars' characters
    return int(hex_digest, 16) 

def gamal_digital_signature_for_DH_public_key(K,K_inverse,alpha_gamal,q_gamal,private_key_gamal,m):
    # pow(alpha_gamal,K) % q_gamal
    S1=mod_pow(alpha_gamal,K,q_gamal)
    S2=K_inverse*(m-private_key_gamal*S1) % (q_gamal-1)
    return S1,S2    

def verify_signatures(alpha_gamal,m,q,public_other_gamal,S1,S2):
    V1=mod_pow(alpha_gamal,m,q)
    # pow(public_key_gamal,S1)*pow(S1,S2) %q
    V2=(mod_pow(public_other_gamal,S1,q)*mod_pow(S1,S2,q))%q
    return V1==V2


def random_less_q(n):
    return random.randrange(n)

def random_coprime_less_than(q):
    if q <= 1:
        return None  # No number less than 1 or 0 can have gcd 1 with itself

    while True:
        number = random.randrange(2, q)  # Start from 2 (avoid 0, 1)
        if gcd(q, number) == 1:
            return number