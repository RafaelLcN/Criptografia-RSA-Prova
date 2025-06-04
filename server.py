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

class RSAServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.public_key, self.private_key = generate_rsa_keys(1024)
        
        log_event('SERVER_START', {
            'host': host,
            'port': port,
            'public_key': self.public_key
        })

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Servidor ativo em {self.host}:{self.port}\nAguardando conexões...")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"\nCliente conectado: {addr}")
            
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, addr),
                daemon=True)
            client_thread.start()

    def handle_client(self, client_socket, addr):
        try:
            # Troca de chaves
            client_socket.send(json.dumps({
                'e': self.public_key[0],
                'n': self.public_key[1]
            }).encode('utf-8'))
            
            client_key_data = client_socket.recv(2048).decode('utf-8')
            client_key = json.loads(client_key_data)
            
            self.clients[addr] = {
                'socket': client_socket,
                'public_key': (client_key['e'], client_key['n'])
            }
            
            # Thread para envio
            send_thread = threading.Thread(
                target=self.send_messages,
                args=(client_socket, addr),
                daemon=True)
            send_thread.start()
            
            # Recebimento de mensagens
            while True:
                data = client_socket.recv(2048).decode('utf-8')
                if not data:
                    break
                    
                encrypted_msg = int(data)
                decrypted_msg = rsa_decrypt(encrypted_msg, self.private_key)
                
                signature = decrypted_msg[-64:]
                message = decrypted_msg[:-64]
                
                if sha256(message) == signature:
                    print(f"[Cliente]: {message}")
                else:
                    print("[ERRO] Assinatura inválida!")
                    
        except ConnectionResetError:
            print("\nCliente desconectado")
        except Exception as e:
            print(f"\nErro na conexão: {str(e)}")
        finally:
            client_socket.close()
            if addr in self.clients:
                del self.clients[addr]

    def send_messages(self, client_socket, addr):
        try:
            while True:
                message = input("[Servidor]: ")
                if message.lower() == 'sair':
                    break
                    
                signature = sha256(message)
                signed_msg = message + signature
                encrypted_msg = rsa_encrypt(
                    signed_msg, 
                    self.clients[addr]['public_key'])
                
                client_socket.send(str(encrypted_msg).encode('utf-8'))
                
        except Exception as e:
            print(f"\nErro ao enviar: {str(e)}")

if __name__ == "__main__":
    server = RSAServer()
    server.start()