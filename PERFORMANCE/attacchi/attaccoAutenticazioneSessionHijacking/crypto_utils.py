from tinyec.ec import Point
from tinyec import registry
import secrets
import hashlib

from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import unpad, pad

ECC_CURVES = {
    1: "secp224r1", 
    2: "secp256r1",
    3: "secp384r1",
    4: "secp521r1",
}

def generate_ecdh_keypair(key_len):
    if key_len not in ECC_CURVES:
        raise ValueError(f"Unsupported ECC key length: {key_len}")
    curve_name = ECC_CURVES[key_len]
    curve = registry.get_curve(curve_name)
    #print(f'Curve {curve} \n\n')
    priv_key = secrets.randbelow(curve.field.n)
    pub_key  = priv_key*curve.g #elliptic curve generator point
    #print(f"Privata {priv_key}\n")
    #print(f"Pubblica {pub_key.x}, {pub_key.y}\n")
    return priv_key, pub_key

def derive_shared_key(priv, pub_x, pub_y, key_len):
    if key_len not in ECC_CURVES:
        raise ValueError(f"Unsupported ECC key length: {key_len}")
    curve_name = ECC_CURVES[key_len]
    curve = registry.get_curve(curve_name)  # o la curva che avevi usato
    pub_key = Point(curve, pub_x, pub_y)
    point_shared = priv*pub_key
    shared_key = ecc_point_to_256_bit_key(point_shared, key_len)
    return shared_key

def ecc_point_to_256_bit_key(point, key_len): #simple key derivation function
    if key_len == 4:
        sha = hashlib.sha256(int.to_bytes(point.x,66,'big'))
        sha.update(int.to_bytes(point.y,66,'big'))
    elif key_len == 3:
        sha = hashlib.sha256(int.to_bytes(point.x,48,'big'))
        sha.update(int.to_bytes(point.y,48,'big'))
    elif key_len == 2:
        sha = hashlib.sha256(int.to_bytes(point.x,32,'big'))
        sha.update(int.to_bytes(point.y,32,'big'))
    else:
        sha = hashlib.sha256(int.to_bytes(point.x,28,'big'))
        sha.update(int.to_bytes(point.y,28,'big'))

    shared_raw = sha.digest()

    return hashlib.sha256(shared_raw + b"encryption").digest(), hashlib.sha256(shared_raw + b"signature").digest()

def encrypt(payload_chiaro, NONCE, KEY, cifrario):
    if cifrario == 1:   #AES.MODE_CBC, lavora su una chiave di 256bits (32bytes)
        cipher = AES.new(KEY, AES.MODE_CBC, NONCE)
        padded = pad(payload_chiaro, AES.block_size)
        #print(f"Block size {AES.block_size}. Paddeding: {padded.hex()}, {len(padded)}")
        encrypted_payload = cipher.encrypt(padded)
        #print(f"Payload cifrato {encrypted_payload.hex()}, {len(encrypted_payload)}")
        
    elif cifrario == 2: #AES.MODE_CBC, lavora su una chiave di 128bits (16bytes)
        cipher = AES.new(KEY[0:129], AES.MODE_CBC, NONCE)
        padded = pad(payload_chiaro, AES.block_size)
        #print(f"Block size {AES.block_size}. Paddeding: {padded.hex()}, {len(padded)}")
        encrypted_payload = cipher.encrypt(padded)
        #print(f"Payload cifrato {encrypted_payload.hex()}, {len(encrypted_payload)}")

    elif cifrario == 3: #CHACHA20, lavora su una chiave di 256bits (32bytes)
        cipher = ChaCha20.new(key=KEY, nonce=NONCE)
        encrypted_payload = cipher.encrypt(payload_chiaro)
    return encrypted_payload

def decrypt(encrypted_payload, NONCE, KEY, cifrario):
    if cifrario == 1:   #AES.MODE_CBC, lavora su una chiave di 256bits (32bytes)
        cipher = AES.new(KEY, AES.MODE_CBC, NONCE)
        decrypted_full = cipher.decrypt(encrypted_payload)
        unpadded = unpad(decrypted_full, AES.block_size)

    elif cifrario == 2: #AES.MODE_CBC, lavora su una chiave di 128bits (16bytes)
        cipher = AES.new(KEY[0:129], AES.MODE_CBC, NONCE)
        decrypted_full = cipher.decrypt(encrypted_payload)
        unpadded = unpad(decrypted_full, AES.block_size)

    elif cifrario == 3: #CHACHA20, lavora su una chiave di 256bits (32bytes)
        cipher = ChaCha20.new(key=KEY, nonce=NONCE)
        unpadded = cipher.decrypt(encrypted_payload)
    return unpadded
