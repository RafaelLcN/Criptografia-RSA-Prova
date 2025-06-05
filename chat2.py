from flask import Flask, request, jsonify
import threading
import requests
import time
from rsa_crypto import *
from sha256 import sha256
import logging
import sys
import json
from datetime import datetime

app = Flask(__name__)
PEER_NAME = "Chat 2" 
PEER_URL = "http://localhost:5000" 
MONITOR_LOG = 'rsa_monitor.log'

# Configurações
public_key, private_key = generate_rsa_keys(1024)
peer_public_key = None
message_queue = []
connection_established = False
stop_threads = False

# Configuração do logging para o monitor
monitor_logger = logging.getLogger('rsa_monitor')
monitor_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(MONITOR_LOG)
file_handler.setFormatter(logging.Formatter('%(message)s'))
monitor_logger.addHandler(file_handler)
monitor_logger.propagate = False

# Desativa logs do Flask
logging.getLogger('werkzeug').disabled = True

def log_event(event_type, data):
    """Registra eventos no log para o monitor (mantido igual)"""
    log_entry = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'type': event_type,
        'data': data
    }
    monitor_logger.info(json.dumps(log_entry))

@app.route('/webhook', methods=['POST'])
def webhook():
    global message_queue
    data = request.json
    if 'message' in data:
        try:
            decrypted = rsa_decrypt(int(data['message']), private_key)
            msg, signature = decrypted[:-64], decrypted[-64:]
            if sha256(msg) == signature:
                message_queue.append(msg)
                log_event('MESSAGE_RECEIVED', {
                    'from': 'Chat 1',
                    'encrypted': str(data['message'])[:20] + '...',
                    'decrypted': msg,
                    'signature': signature[:16] + '...'
                })
                return jsonify({'status': 'received'}), 200
        except Exception as e:
            print(f"Erro no webhook: {e}")
    return jsonify({'error': 'invalid request'}), 400

@app.route('/exchange_keys', methods=['POST'])
def exchange_keys():
    global peer_public_key, connection_established
    try:
        peer_data = request.json
        peer_public_key = (peer_data['e'], peer_data['n'])
        connection_established = True
        log_event('KEY_EXCHANGE', {
            'peer': 'Chat 1',  # Alterado para Chat 1
            'public_key': peer_public_key
        })
        return jsonify({
            'e': public_key[0],
            'n': public_key[1],
            'peer': PEER_NAME
        })
    except Exception as e:
        print(f"Erro na troca de chaves: {e}")
        return jsonify({'error': 'key exchange failed'}), 400

def send_message(message):
    if not peer_public_key:
        return False
    
    try:
        signature = sha256(message)
        encrypted = rsa_encrypt(message + signature, peer_public_key)
        log_event('MESSAGE_SENT', {
            'to': 'Chat 1', 
            'encrypted': str(encrypted)[:20] + '...',
            'decrypted': message,
            'signature': signature[:16] + '...'
        })
        requests.post(f"{PEER_URL}/webhook", json={'message': str(encrypted)})
        return True
    except Exception as e:
        print(f"Erro ao enviar mensagem: {e}")
        return False

def message_receiver():
    global stop_threads
    while not stop_threads:
        if message_queue:
            msg = message_queue.pop(0)
            sys.stdout.write(f"\r[Chat 1] >>> {msg}\n[{PEER_NAME}] >>> ") 
            sys.stdout.flush()
        time.sleep(0.1)

def establish_connection():
    global connection_established
    while not connection_established and not stop_threads:
        try:
            response = requests.post(
                f"{PEER_URL}/exchange_keys",
                json={'e': public_key[0], 'n': public_key[1]},
                timeout=2
            )
            if response.status_code == 200:
                peer_data = response.json()
                peer_public_key = (peer_data['e'], peer_data['n'])
                connection_established = True
                print("\nConexão estabelecida com sucesso!\n")
        except:
            time.sleep(1)

def start_chat():
    global stop_threads
    
    # Inicia threads
    threading.Thread(target=message_receiver, daemon=True).start()
    threading.Thread(target=establish_connection, daemon=True).start()
    
    print(f"\n{PEER_NAME} iniciado. Aguardando conexão...\n")
    
    while not connection_established and not stop_threads:
        time.sleep(0.1)
    
    while True:
        try:
            message = input(f"[{PEER_NAME}] >>> ")
            if message.lower() == 'sair':
                stop_threads = True
                break
                
            if send_message(message):
                sys.stdout.write(f"\rVocê: {message}\n")
                sys.stdout.flush()
                
        except KeyboardInterrupt:
            stop_threads = True
            print("\nEncerrando chat...")
            break

def run_flask():
    app.run(port=5001)  # Alterado para porta 5001

if __name__ == "__main__":
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    time.sleep(1)
    start_chat()
