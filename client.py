import socket
import threading
import json
from datetime import datetime
from rsa_crypto import *
from sha256 import sha256

MONITOR_LOG = 'rsa_monitor.log'

def log_event(event_type, data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'type': event_type,
        'data': data
    }
    with open(MONITOR_LOG, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

class RSAClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key, self.private_key = generate_rsa_keys(1024)
        self.server_public_key = None
        
        log_event('CLIENT_START', {
            'host': host,
            'port': port,
            'public_key': self.public_key
        })

    def connect(self):
        self.client_socket.connect((self.host, self.port))
        print(f"Conectado ao servidor {self.host}:{self.port}")
        
        # Troca de chaves
        server_key_data = self.client_socket.recv(2048).decode('utf-8')
        self.server_public_key = json.loads(server_key_data)
        
        self.client_socket.send(json.dumps({
            'e': self.public_key[0],
            'n': self.public_key[1]
        }).encode('utf-8'))
        
        # Thread para recebimento
        receive_thread = threading.Thread(
            target=self.receive_messages,
            daemon=True)
        receive_thread.start()
        
        self.send_messages()

    def send_messages(self):
        try:
            while True:
                message = input("[Cliente]: ")
                if message.lower() == 'sair':
                    break
                
                signature = sha256(message)
                signed_msg = message + signature
                encrypted_msg = rsa_encrypt(
                    signed_msg,
                    (self.server_public_key['e'], self.server_public_key['n']))
                
                self.client_socket.send(str(encrypted_msg).encode('utf-8'))
                
        except Exception as e:
            print(f"\nErro ao enviar: {str(e)}")
        finally:
            self.client_socket.close()

    def receive_messages(self):
        try:
            while True:
                data = self.client_socket.recv(2048).decode('utf-8')
                if not data:
                    print("\nServidor desconectado")
                    break
                
                encrypted_msg = int(data)
                decrypted_msg = rsa_decrypt(encrypted_msg, self.private_key)
                
                signature = decrypted_msg[-64:]
                message = decrypted_msg[:-64]
                
                if sha256(message) == signature:
                    print(f"[Servidor]: {message}")
                else:
                    print("\n[ERRO] Assinatura inválida!")
                    
        except ConnectionResetError:
            print("\nConexão com servidor perdida")
        except Exception as e:
            print(f"\nErro na conexão: {str(e)}")

if __name__ == "__main__":
    client = RSAClient()
    client.connect()