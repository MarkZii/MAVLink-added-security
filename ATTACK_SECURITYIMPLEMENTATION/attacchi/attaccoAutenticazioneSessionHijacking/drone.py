from pymavlink import mavutil
from pymavlink.dialects.v20 import secure as mavlink2
from ecdsa import SigningKey, VerifyingKey, NIST192p, util
import time, threading, os
from crypto_utils import generate_ecdh_keypair, derive_shared_key, encrypt, decrypt

ID_key_exchange = (10003, 10004, 10005)
KEY_CRITTO = b''
KEY_SIGNA = b'shannon'
quale_cifrario = 1
link_id = 1
confidenzialita_attiva = False

ECC_CURVES = {
    1: "secp224r1", 
    2: "secp256r1",
    3: "secp384r1",
    4: "secp521r1",
}
SYMMETRIC_CIPHER = {
    1: "AES-CBC-256", 
    2: "AES-CBC-128",
    3: "ChaCha20-256"
}

confidenzialita_attiva = False

# Connessione drone --> GCS
conn = mavutil.mavlink_connection('udpin:127.0.0.1:14550', dialect='secure')
conn.force_mavlink2 = True
mav = mavlink2.MAVLink(conn, srcSystem=255)
mav.robust_parsing = True
mav.signing.secret_key = KEY_SIGNA
mav.signing.link_id = link_id
mav.signing.sign_outgoing = True


'''def calcoloECDSA():
    global vk_loaded
    print("Genero la coppie di chiavi ...")
    sk = SigningKey.generate(curve=NIST192p) # La chiave privata viene tenuta segreta
    vk = sk.get_verifying_key() # Ottengo la chiave pubblica (vk).

    print("Esporto su file .pem la chiave pubblica ...")
    
    with open('public_key_drone.pem', 'wb') as f: # Serializzazione e salvataggio dei byte
        f.write(vk.to_string())
    print("Chiave pubblica salvata in 'public_key.pem'")

    print(f"Stampa della chiave pubblica: {vk.to_string().hex()}")

    #CARICO LA CHIAVE PUBBLICA DEL DRONE PER PERMETTERE POI L'AUTENTICAZIONE
    timeout = 30  # Secondi
    start_time = time.time()
    file_da_attendere = "public_key_gcs.pem"
    while not os.path.exists(file_da_attendere):
        if time.time() - start_time > timeout:
            print("Errore: Timeout raggiunto, il file non è stato trovato.")
            break
        print(f"In attesa del file '{file_da_attendere}'...")
        time.sleep(1) # Attendi 1 secondo prima di ricontrollare
    else:
        print("File trovato!")
        try:
            with open(file_da_attendere, 'rb') as f:
                vk_string = f.read()
            print(f"Stampa della chiave pubblica da file: {vk_string.hex()}")
            vk_loaded = VerifyingKey.from_string(vk_string, curve=NIST192p) #Ricostruzione dell'oggetto VerifyingKey
            print("Chiave pubblica caricata con successo.") #E' possibile usare vk_loaded per verificare firme
            return True
        except Exception as e:
            print(f"Errore durante il caricamento della chiave: {e}")
    return False'''


# Inoltro periodico dell'heartbeat
def heart():
    while True:
        mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_QUADROTOR,0, 0, 0, 0)
        time.sleep(2.0)

threading.Thread(target=heart, daemon=True).start()

def decifratura(frame_org):
    global mav
    try:
        #print(f"Frame cifrato: {frame_org.hex()}")
        msg_id = int.from_bytes(frame_org[7:10], "little")
        if msg_id in ID_key_exchange:
            return mav.parse_char(frame_org)
            
        HEADER_LEN = 0
        if hex(frame_org[0]) == hex(253):
            HEADER_LEN = 10
        else:
            HEADER_LEN = 6
        if quale_cifrario == 3:
            iv = frame_org[-24:]
        else:
            iv = frame_org[-16:]

        if quale_cifrario == 3:
            frame = frame_org[:-24]
        else:
            frame = frame_org[:-16]

        payload_len = frame[1]
        if payload_len > 240:
            payload_len = payload_len+1
        payload_start = HEADER_LEN
        payload_end = payload_start + payload_len
        encrypted_payload = frame[payload_start:payload_end]

        # Decifra il payload
        unpadded = decrypt(encrypted_payload, iv, KEY_CRITTO, quale_cifrario)

        # Ricostruisce il frame con payload decifrato
        frame2 = frame[:1] + bytes([len(unpadded)]) + frame[2:]
        decrypted_frame = frame2[:payload_start] + unpadded + frame2[payload_end:]

        #print(f"Frame originale: {decrypted_frame.hex()}")
        msg = mav.parse_char(decrypted_frame)
        if msg:
            return msg
        #else: #TODO testare
            #print("[DRONE] Nessun messaggio valido trovato nel payload decifrato.")
            
        #return msg
    except Exception as e:
        #print(f"[GCS] Errore nella decifratura/parsing: {e}")
        return e
print("AVVIATO")


# Rimane attivo per sempre finchè non viene spento
while True:
    byte = conn.recv()
    if byte is None or len(byte) < 12 or (hex(byte[0]) != hex(253) and hex(byte[0]) != hex(254)):
        time.sleep(0.001)
        continue
    
    if not confidenzialita_attiva:
        print(f"[DRONE] Frame NON cifrato ricevuto")
        try:
            
            msg = mav.parse_char(byte)
            if msg.get_type() == "CHANGE_MODE" and getattr(msg, "_signed", False):
                mav.key_exchange_ack_send(target_system=msg.target_system, target_component=0, status=1)
                if msg.encryption == 1:
                    confidenzialita_attiva = True
                else:
                    confidenzialita_attiva = False
                print(f"Confidenzialità posta ad {msg.encryption}")

            if msg.get_type() == "KEY_PUBLIC_EXCHANGE" and getattr(msg, "_signed", False):
                print("Richiesta di nuovo scambio chiavi correttamente firmato. Sorgente autenticata")
                pub_key_gcs_x = int.from_bytes(msg.public_key_x, 'big')
                pub_key_gcs_y = int.from_bytes(msg.public_key_y, 'big')
                                            
                curve = msg.key_len
                quale_cifrario = msg.symmetric_cipher
                priv_drone, pub_drone = generate_ecdh_keypair(curve) # genero la mia keypair e invio la public key
                mav.key_public_exchange_send(
                    target_system=msg.target_system,
                    target_component=0,
                    public_key_x=pub_drone.x.to_bytes(125, 'big'),
                    public_key_y=pub_drone.y.to_bytes(125, 'big'),
                    key_len=curve,
                    symmetric_cipher=quale_cifrario
                )
                print("Chiave pubblica inviata al GCS")

                # Attendo l'ack dal GCS
                timeout = 5  # Secondi
                start_time = time.time()
                while time.time() - start_time < timeout:
                    byte = conn.recv()
                    if not byte:
                        time.sleep(0.001)  # Aspetta un po' per non consumare CPU
                        continue
                    break

                msg = mav.parse_char(byte)
                if msg.get_type() == "KEY_EXCHANGE_ACK" and msg.status == 1 and getattr(msg, "_signed", False):
                    # Scambio di chiavi avvenuto con successo calcolo la chiave simmetrica
                    KEY_CRITTO, KEY_SIGNA = derive_shared_key(priv_drone, pub_key_gcs_x, pub_key_gcs_y, curve)
                    mav.signing.secret_key = KEY_SIGNA
                    print("Scambio di chiavi avvenuto con successo:")
                    print("     - chiave simmetrica concordata: ", KEY_CRITTO.hex())
                    print("     - chiave di firma concordata:   ", KEY_SIGNA.hex())
                    print("     - cifrario simmetrico scelto:   ", SYMMETRIC_CIPHER.get(quale_cifrario))
                    print("     - curva ellittica utilizzata:   \n", ECC_CURVES.get(curve))
                    #continue
                else:
                    print("Scambio di chiavi NON avvenuto.")

            elif getattr(msg, "_signed", False):
                print(f"GCS --> DRONE: {msg.get_type()} (firmato)")
            
            elif msg.get_type() == "BAD_DATA":
                print("MESSAGGIO RICEVUTO ERRATO")
                mav = mavlink2.MAVLink(conn)  #, srcSystem=189, srcComponent=200)
                mav.robust_parsing = True
                mav.signing.secret_key = KEY_SIGNA
                mav.signing.link_id = link_id
                mav.signing.sign_outgoing = True

        except Exception as e:
            print(f"ERRORE, messaggio scartato in quanto la signature da parte del GCS è attiva OR scambio di chiavi non avvenuto.")
    elif confidenzialita_attiva:
        print(f"[DRONE] Frame cifrato ricevuto")
        try:
            msg = decifratura(byte)
            if msg.get_type() == "CHANGE_MODE" and getattr(msg, "_signed", False):
                mav.key_exchange_ack_send(target_system=msg.target_system, target_component=0, status=1)
                if msg.encryption == 1:
                    confidenzialita_attiva = True
                else:
                    confidenzialita_attiva = False
                print(f"Confidenzialità posta ad {msg.encryption}")

            if msg.get_type() == "KEY_PUBLIC_EXCHANGE" and getattr(msg, "_signed", False):
                print("Richiesta di nuovo scambio chiavi correttamente firmato. Sorgente autenticata")
                pub_key_gcs_x = int.from_bytes(msg.public_key_x, 'big')
                pub_key_gcs_y = int.from_bytes(msg.public_key_y, 'big')
                                                
                curve = msg.key_len
                quale_cifrario = msg.symmetric_cipher
                priv_drone, pub_drone = generate_ecdh_keypair(curve) # genero la mia keypair e invio la public key
                print(f"{priv_drone} {pub_drone} \n\n")
                mav.key_public_exchange_send(
                    target_system=msg.target_system,
                    target_component=0,
                    public_key_x=pub_drone.x.to_bytes(125, 'big'),
                    public_key_y=pub_drone.y.to_bytes(125, 'big'),
                    key_len=curve,
                    symmetric_cipher=quale_cifrario
                )
                print("Chiave pubblica inviata al GCS")

                # Attendo l'ack dal GCS
                timeout = 5  # Secondi
                start_time = time.time()
                while time.time() - start_time < timeout:
                    byte = conn.recv()
                    if not byte:
                        time.sleep(0.001)  # Aspetta un po' per non consumare CPU
                        continue
                    break

                msg = mav.parse_char(byte) #TODO KEY_EXCHANGE_ACK non giunto 
                if msg.get_type() == "KEY_EXCHANGE_ACK" and msg.status == 1 and getattr(msg, "_signed", False):
                    # Scambio di chiavi avvenuto con successo calcolo la chiave simmetrica
                    KEY_CRITTO, KEY_SIGNA = derive_shared_key(priv_drone, pub_key_gcs_x, pub_key_gcs_y, curve)
                    mav.signing.secret_key = KEY_SIGNA
                    print("Scambio di chiavi avvenuto con successo:")
                    print("     - chiave simmetrica concordata: ", KEY_CRITTO.hex())
                    print("     - chiave di firma concordata:   ", KEY_SIGNA.hex())
                    print("     - cifrario simmetrico scelto:   ", SYMMETRIC_CIPHER.get(quale_cifrario))
                    print("     - curva ellittica utilizzata:   \n", ECC_CURVES.get(curve))
                else:
                    print("Scambio di chiavi NON avvenuto.")

            elif getattr(msg, "_signed", False): #TODO implementare anche la roba non cifrata
                print(f"GCS --> DRONE: {msg.get_type()} (firmato)")
            
            elif msg.get_type() == "BAD_DATA":
                print("MESSAGGIO RICEVUTO ERRATO")
                mav = mavlink2.MAVLink(conn)  #, srcSystem=189, srcComponent=200)
                mav.robust_parsing = True
                mav.signing.secret_key = KEY_SIGNA
                mav.signing.link_id = link_id
                mav.signing.sign_outgoing = True
        except Exception:
            print("ERRORE NELLA DECIFRATURA.")
    print("\n")
