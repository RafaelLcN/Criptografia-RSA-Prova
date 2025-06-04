import json
import time
import os
from datetime import datetime

class RSAMonitor:
    def __init__(self, log_file='rsa_monitor.log'):
        self.log_file = log_file
        self.last_position = 0
        self.setup_log()
    
    def setup_log(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("")
    
    def check_updates(self):
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                file_size = f.tell()
                
                if file_size < self.last_position:
                    self.last_position = 0
                    f.seek(0)
                elif self.last_position > 0:
                    f.seek(self.last_position)
                
                new_entries = f.read()
                self.last_position = f.tell()
                return new_entries
        except Exception as e:
            print(f"Erro ao ler log: {e}")
            return ""

    def display_event(self, event):
        try:
            timestamp = datetime.strptime(event['timestamp'], "%Y-%m-%d %H:%M:%S").strftime("%H:%M:%S")
            
            if event['type'] == 'KEY_EXCHANGE':
                print(f"\n[{timestamp}]  Troca de Chaves com {event['data']['peer']}")
                print(f"   Chave pública (e): {event['data']['public_key'][0]}")
                print(f"   Chave pública (n): {event['data']['public_key'][1][:20]}...")
            elif event['type'] == 'MESSAGE_SENT':
                print(f"\n[{timestamp}]  Mensagem enviada para {event['data']['to']}")
                print(f"   Conteúdo: {event['data']['decrypted']}")
                print(f"   Criptografado: {event['data']['encrypted']}")
                print(f"   Assinatura: {event['data']['signature']}")
            elif event['type'] == 'MESSAGE_RECEIVED':
                print(f"\n[{timestamp}]  Mensagem recebida de {event['data']['from']}")
                print(f"   Conteúdo: {event['data']['decrypted']}")
                print(f"   Criptografado: {event['data']['encrypted']}")
                print(f"   Assinatura: {event['data']['signature']}")
            
            print("-" * 50)
        except Exception as e:
            print(f"\nErro ao exibir evento: {e}")

    def real_time_monitoring(self):
        print("\n=== MONITOR RSA - ATIVO ===")
        print("Monitorando atividades em tempo real...")
        print("Pressione Ctrl+C para sair\n")
        
        try:
            while True:
                new_content = self.check_updates()
                if new_content.strip():
                    for line in new_content.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                event = json.loads(line)
                                self.display_event(event)
                            except json.JSONDecodeError:
                                continue
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nMonitoramento encerrado.")

if __name__ == "__main__":
    monitor = RSAMonitor()
    monitor.real_time_monitoring()