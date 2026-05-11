from pymavlink import mavutil
from pymavlink.dialects.v20 import secure as mavlink2
from ecdsa import SigningKey, VerifyingKey, NIST192p, util
import time, threading, hashlib, os, binascii
from crypto_utils import generate_ecdh_keypair, derive_shared_key, encrypt, decrypt

ID_key_exchange = (10003, 10004, 10005)
KEY_CRITTO = b''
KEY_SIGNA = b'shannon'
link_id = 1
quale_cifrario = 1
confidenzialita_attiva = False
pausa = False

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

# Connessione UDP MAVLink in ascolto GCS --> drone
conn = mavutil.mavlink_connection('udpout:127.0.0.1:14550', dialect='secure') #,  source_system=1
conn.force_mavlink2 = True
mav = mavlink2.MAVLink(conn, srcSystem=50)
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
    
    with open('public_key_gcs.pem', 'wb') as f: # Serializzazione e salvataggio dei byte
        f.write(vk.to_string())
    print("Chiave pubblica salvata in 'public_key.pem'")

    print(f"Stampa della chiave pubblica: {vk.to_string().hex()}")

    #CARICO LA CHIAVE PUBBLICA DEL DRONE PER PERMETTERE POI L'AUTENTICAZIONE
    timeout = 30  # Secondi
    start_time = time.time()
    file_da_attendere = "public_key_drone.pem"
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

def invio_key_public_exchange(num_curva, cifrario):
    priv_gcs, pub_gcs = generate_ecdh_keypair(num_curva)
    print("Coppie di chiavi del GCS calcolate")
    # invio la mia pubkey
    mav.key_public_exchange_send(
        target_system=1,
        target_component=0,
        public_key_x=pub_gcs.x.to_bytes(125, 'big'),
        public_key_y=pub_gcs.y.to_bytes(125, 'big'),
        key_len=num_curva,
        symmetric_cipher=cifrario
    )
    return priv_gcs

# CONCORDO LE CHIAVI DI CIFRATURA
# Per diminuire i messaggi scambiati effettuo la richiesta di nuove chiavi inviando già la chiave pubblica.
def concordo_chiavi_simmetriche(num_curva, cifrario):
    global KEY_CRITTO, KEY_SIGNA, quale_cifrario, pausa
    pausa = True

    while True:
        msg = conn.recv_match(blocking=False)
        if msg is None:
            break

    # Attendo le chiavi dal drone. Attendo max per 5 secondo altrimenti rinvio nuove chiavi.
    timeout = 5  # Secondi
    riuscito = False
    for i in range(0,4):
        start_time = time.time()
        print("\n\n")
        ricevuto = False
        priv_gcs = invio_key_public_exchange(num_curva, cifrario) # genero la mia coppia e calcolo shared key
        print(f"Inoltrata la chiave pubblica + richiesta scambio chiave inviata al drone. Tentativo num. {i}")
        try:
            while time.time() - start_time < timeout and ricevuto == False:
                byte = conn.recv()
                if not byte:
                    time.sleep(0.001)  # Aspetta un po' per non consumare CPU
                    continue
                msg = mav.parse_char(byte)
                if msg.get_type() == "KEY_PUBLIC_EXCHANGE":
                    ricevuto = True
                    break
            #print(f"Ricevuto {msg.get_type()}")
            if ricevuto and msg.get_type() == "KEY_PUBLIC_EXCHANGE" and msg.key_len == num_curva and getattr(msg, "_signed", False):
                print(f"Ricevo la chiave pubblica del drone")
                pub_key_drone_x = int.from_bytes(msg.public_key_x, 'big')
                pub_key_drone_y = int.from_bytes(msg.public_key_y, 'big')
                #print(f"{pub_key_drone_x} {pub_key_drone_y} \n\n")
                mav.key_exchange_ack_send(target_system=msg.target_system, target_component=0, status=1)
                riuscito = True
                break
            else:
                print("Messaggio ricevuto o ERRATO o signature errata. Ritento")

        except Exception as e:
            print(f"ERRORE, messaggio scartato in quanto la signature è errata. Scambio di chiavi non avvenuto. Ritento {e}")

    if riuscito:
        # Scambio di chiavi avvenuto con successo calcolo la chiave simmetrica
        KEY_CRITTO, KEY_SIGNA = derive_shared_key(priv_gcs, pub_key_drone_x, pub_key_drone_y, num_curva)
        mav.signing.secret_key = KEY_SIGNA
        quale_cifrario = cifrario
        print("Scambio di chiavi avvenuto con successo:")
        print("     - chiave simmetrica concordata: ", KEY_CRITTO.hex())
        print("     - chiave di firma concordata:   ", KEY_SIGNA.hex())
        print("     - cifrario simmetrico scelto:   ", SYMMETRIC_CIPHER.get(quale_cifrario))
        print("     - curva ellittica utilizzata:   \n\n", ECC_CURVES.get(num_curva))
    else:
        print("Scambio di chiavi NON avvenuto.")

    pausa = False
    return riuscito
        
def cifratura(msg): #TODO
    if quale_cifrario == 3:
        nonce = os.urandom(24)
    else:
        nonce = os.urandom(16)

    frame = msg.pack(mav) # Pack del messaggio per ottenere frame MAVLink v2
    #print(f"Frame serializzato originale: {frame.hex()}")
    
    # Calcola offset payload
    HEADER_LEN = 0
    if hex(frame[0]) == hex(253):
        HEADER_LEN = 10 # The minimum packet length is 12 bytes for acknowledgment packets without payload.
    else:
        HEADER_LEN = 6
    payload_len = frame[1] # prende il campo len dal frame
    payload_start = HEADER_LEN
    payload_end = payload_start + payload_len

    # Cifra solo il payload, quindi prendo solo i byte di esso
    payload_chiaro = frame[payload_start:payload_end]
    encrypted_payload = encrypt(payload_chiaro, nonce, KEY_CRITTO, quale_cifrario)

    # Ricostruisce frame con payload cifrato
    # Attenzione! metto come lunghezza del payload la lunghezza del testo cifrato con padding 
    if len(encrypted_payload) > 240:
        frame2 = frame[:1] + bytes([255]) + frame[2:]
    else:
        frame2 = frame[:1] + bytes([len(encrypted_payload)]) + frame[2:]
    encrypted_frame = frame2[:payload_start] + encrypted_payload + frame2[payload_end:] + nonce
    
    return encrypted_frame

# Inoltro periodico dell'heartbeat
'''def heart():
    while True:
        msg = conn.recv_match(blocking=True)
        print(msg)

threading.Thread(target=heart, daemon=True).start()'''

def attiva_cifratura(attivo):
    global confidenzialita_attiva, pausa
    pausa = True
    timeout = 5  # Secondi
    riuscito = False
    for i in range(0,4): 
        start_time = time.time()
        print("\n\n")
        ricevuto = False
        mav.change_mode_send(target_system=1, target_component=0, encryption=attivo)
        print(f"Inoltrata la richiesta per passare in modalità {attivo}. Richiesta numero {i}")
        try:
            while time.time() - start_time < timeout and ricevuto == False:
                byte = conn.recv()
                if not byte:
                    time.sleep(0.001)  # Aspetta un po' per non consumare CPU
                    continue
                msg = mav.parse_char(byte)
                if msg.get_type() == "KEY_EXCHANGE_ACK":
                    ricevuto = True
                    break
            if ricevuto and msg.get_type() == "KEY_EXCHANGE_ACK" and getattr(msg, "_signed", False) and msg.status == 1:
                print(f"Ricevuto l'ack ({msg.get_type()}) di conferma switch\n")
                if attivo == 1:
                    confidenzialita_attiva = True
                else:
                    confidenzialita_attiva = False
                riuscito = True
                break
            else:
                print("Messaggio di ACK ricevuto o ERRATO o signature errata. Ritento\n")
        except Exception as e:
            print(f"ERRORE, messaggio scartato in quanto la signature è errata. Switch non avvenuto\n")
    if not riuscito:
        print("Switch in modalità cifrata non riuscito")
    pausa = False

print("AVVIATO")

'''
mav.heartbeat_send(
    mavutil.mavlink.MAV_TYPE_GCS,
    mavutil.mavlink.MAV_AUTOPILOT_INVALID,
    0, 0, 0
)
# aspetta la connessione
conn.wait_heartbeat()
print("Heartbeat ricevuto dal sistema", conn.target_system)
'''

print("INVIO SEQUENZA DI MESSAGGI SENZA CONFIDENZIALITA'")
# Costruisco messaggi standard
msg = mav.command_long_send(
    target_system=1,
    target_component=1,
    command=22,            # MAV_CMD_NAV_TAKEOFF
    confirmation=0,
    param1=42, param2=0, param3=0, param4=0,
    param5=0, param6=0, param7=10
)
print(f"Inviato: command_long\n")
time.sleep(3.0)

msg = mav.statustext_send(
    severity=6,  # Informazione
    text="Test messaggio STATUSTEXT dal GCS".encode('utf-8')
)
print(f"Inviato: statustext\n")
time.sleep(3.0)

msg = mav.statustext_send(
    severity=6,
    text="Prova STATUSTEXT da GCS.".encode('utf-8')
)
print(f"Inviato: statustext\n")
time.sleep(3.0)

msg = mav.statustext_send(
    severity=6,  # Informazione
    text="Test messaggio STATUSTEXT dal GCS".encode('utf-8')
)
print(f"Inviato: statustext\n")
time.sleep(3.0)

msg = mav.statustext_send(
    severity=6,
    text="Prova STATUSTEXT da GCS.".encode('utf-8')
)
print(f"Inviato: statustext\n")
time.sleep(3.0)


# Concordo chiavi di cifratura
if concordo_chiavi_simmetriche(2,2):
    print("CHIAVI CONCOORDATE\n\n")
    time.sleep(3.0)

    attiva_cifratura(1) #attiva
    if confidenzialita_attiva:
        # Costruisco messaggi standard
        msg = mav.command_long_encode(
            target_system=1,
            target_component=1,
            command=22,            # MAV_CMD_NAV_TAKEOFF
            confirmation=0,
            param1=42, param2=0, param3=0, param4=0,
            param5=0, param6=0, param7=10
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(3.0)

        msg = mav.statustext_encode(
            severity=6,  # Informazione
            text="Test messaggio STATUSTEXT dal GCS".encode('utf-8')
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(3.0)

        msg = mav.statustext_encode(
            severity=6,
            text="Prova STATUSTEXT da GCS.".encode('utf-8')
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(3.0)

        msg = mav.param_value_encode(
            param_id=b'MAX_ALT',     # 16 byte max, padded automatically
            param_value=120.0,
            param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
            param_count=1,
            param_index=0
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(3.0)

        msg = mav.command_long_encode(
            target_system=1,
            target_component=1,
            command=mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
            confirmation=0,
            param1=1,  # 1 = Arm, 0 = Disarm
            param2=0,
            param3=0,
            param4=0,
            param5=0,
            param6=0,
            param7=0
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(3.0)

'''
    attiva_cifratura(0) #non attiva
    if not confidenzialita_attiva:
        msg = mav.global_position_int_send(
            time_boot_ms=int(time.time() * 1000) % 4294967295,
            lat=int(45.0703 * 1e7),     # Torino
            lon=int(7.6869 * 1e7),
            alt=int(300.0 * 1000),      # mm
            relative_alt=int(50.0 * 1000),
            vx=0, vy=0, vz=0,
            hdg=65535                   # 65535 = Unknown
        )
        print(f"Inviato: {msg}\n\n")
        time.sleep(3.0)

        print("PAYLOAD DI 239 BYTES")
        # Invia messaggio STATUSTEXT
        msg = mav.play_tune_v2_send( #8 + 207 + 16 + 8
            target_system=0,  # Informazione
            target_component=0,
            format=1,
            tune="Test messaggio STATUSTEXT dal GCS ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao".encode('utf-8')
        )
        print(f"Inviato: {msg}\n\n")
        # Invia frame grezzo

        msg = mav.global_position_int_send(
            time_boot_ms=int(time.time() * 1000) % 4294967295,
            lat=int(45.0703 * 1e7),     # Torino
            lon=int(7.6869 * 1e7),
            alt=int(300.0 * 1000),      # mm
            relative_alt=int(50.0 * 1000),
            vx=0, vy=0, vz=0,
            hdg=65535                   # 65535 = Unknown
        )
        print(f"Inviato: {msg}\n\n")
        time.sleep(3.0)

        print("PAYLOAD DI 239 BYTES")
        # Invia messaggio STATUSTEXT
        msg = mav.play_tune_v2_encode( #8 + 207 + 16 + 8
            target_system=0,  # Informazione
            target_component=0,
            format=1,
            tune="Test messaggio STATUSTEXT dal GCS ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao come stai.ciao".encode('utf-8')
        )
        print(msg)
        # Invia frame grezzo
        conn.write(cifratura(msg))
        print("Frame cifrato inviato\n\n")'''
