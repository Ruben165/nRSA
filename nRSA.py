import time
import math
import sympy
import random
import base64

# Determine Prime Numbers
def gen_n_prime():
  iter = None
  list_of_prime = []

  while True:
    try:
      iter = int(input("How many prime numbers ? (2-5) [the numbers will be auto-generated]: "))
      if(iter>=2 and iter<=5):
        break
      else:
        print("The number must be ranging from 2 to 5 (inclusive, only integer)!\n")
    except:
      print("Invalid Input! Please insert only numerical characters!\n")

  for i in range(iter):
    while True:
      prime_num = random.randint(2**1023, 2**1024) # The numbers that will be auto-generated will be at least 2^1023 and at most 2^1024
      if(sympy.isprime(prime_num) and (prime_num not in list_of_prime)):
        list_of_prime.append(prime_num)
        break

  return list_of_prime

# Determine Public Key
def gen_public_key(phi_n, e=65537):
  while(math.gcd(e, phi_n)!=1 or (e<1 or e>phi_n)):
    e = random.randint(2, phi_n)
  return e

# Calculate Private Key
def gen_private_key(e, phi_n):
  d, x1, x2, y1 = 0, 0, 1, 1
  m = phi_n

  while(e>0):
    k = m // e
    r = m - k * e

    m, e = e, r

    x = x2 - k * x1
    y = d - k * y1

    x2, x1 = x1, x
    d, y1 = y1, y

  while(d<0):
    d = d + phi_n

  return d % phi_n

# Generate Public - Private Key Pairs
def gen_keypairs():
  list_of_prime = gen_n_prime()
  n = math.prod(list_of_prime)

  for_phi = [x - 1 for x in list_of_prime]
  phi_n  = math.prod(for_phi)

  pub_key = (gen_public_key(phi_n), n)
  priv_key = (gen_private_key(pub_key[0], phi_n), n)

  return pub_key, priv_key, list_of_prime

# Encryption
def encrypt(msg, e, n):
  msg_byte = msg.encode('utf-8')
  piece_size = len(str(n)) // 3
  piece_size = 1 if piece_size==0 else piece_size
  pieces = [msg_byte[i:i + piece_size] for i in range(0, len(msg_byte), piece_size)]

  cip_list = [pow(int.from_bytes(piece, byteorder='big'), e, n) for piece in pieces]
  cip_byte = b','.join([str(c).encode('utf-8') for c in cip_list])

  return base64.b64encode(cip_byte).decode('utf-8')

# Decryption
def decrypt(cip_msg, d, n):
  cip_byte = base64.b64decode(cip_msg.encode('utf-8'))
  cip_list = list(map(int, cip_byte.decode('utf-8').split(',')))
  dec_byte = [pow(piece, d, n).to_bytes((pow(piece, d, n).bit_length() + 7) // 8, byteorder='big') for piece in cip_list]
  return b''.join(dec_byte).decode('utf-8')

# Menu
def nRSA():
  counter = 0
  while True:
    try:
      print("nRSA")
      print("1. Encryption\n2. Decryption\n3. Generate Key Pairs\n4. Exit")
      choice = input("Enter Your Choice: ")

      if(choice=='1'):
        msg = input("Enter Plain text For Encryption: ")
        time.sleep(1)
        e, n = map(int, input("Enter your public key (e,n) without the brackets: ").split(','))
        time.sleep(1)
        print(f"\nCipher Text: {encrypt(msg, e, n)}\n")

      elif(choice=='2'):
        cip_msg = input("Enter Cipher Text for Decryption: ")
        time.sleep(1)
        d, n = map(int, input("Enter your private key (d,n) without the brackets: ").split(','))
        time.sleep(1)
        print(f"\nPlain Text: {decrypt(cip_msg, d, n)}\n")

      elif(choice=='3'):
        pub_key, priv_key, _ = gen_keypairs()
        time.sleep(1)
        print(f"\nPublic Key: {pub_key}\n\nPrivate Key: {priv_key}\n")

      elif(choice=='4'):
        print("\nPlease Wait...")
        time.sleep(1)
        print("\nProgram Ended Successfully!\n")
        break

      else:
        print("\nInvalid Input!\n")

    except:
      print("\nError!\n")
      continue

if __name__ == "__main__":
  nRSA()