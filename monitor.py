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
                f.write("=== INÍCIO DO LOG ===\n")
    
    def check_updates(self):
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)  # Vai para o final do arquivo
                file_size = f.tell()
                
                if file_size < self.last_position:
                    # Arquivo foi truncado ou reiniciado
                    self.last_position = 0
                    f.seek(0)
                else:
                    f.seek(self.last_position)
                
                new_entries = f.read()
                self.last_position = f.tell()
                return new_entries
        except FileNotFoundError:
            return ""
        except Exception as e:
            print(f"Erro ao ler log: {e}")
            return ""
    
    def display_event(self, event):
        try:
            data = json.loads(event)
            timestamp = data.get('timestamp', '')
            event_type = data.get('type', 'UNKNOWN')
            event_data = data.get('data', {})
            
            print(f"\n[{timestamp}] {event_type}:")
            print(json.dumps(event_data, indent=2, ensure_ascii=False))
            print("-" * 50)
        except json.JSONDecodeError:
            print(f"\nRaw log entry: {event}")
    
    def real_time_monitoring(self):
        print("\n=== MONITOR RSA - MODO TEMPO REAL ===")
        print("Monitorando atividades... Pressione Ctrl+C para sair\n")
        
        try:
            while True:
                new_content = self.check_updates()
                if new_content.strip():
                    for line in new_content.splitlines():
                        if line.strip():
                            self.display_event(line)
                time.sleep(0.3)
        except KeyboardInterrupt:
            print("\nMonitoramento encerrado.")
    
    def show_menu(self):
        while True:
            print("\n=== MENU DO MONITOR ===")
            print("1. Monitorar em tempo real")
            print("2. Ver log completo")
            print("3. Limpar log")
            print("4. Sair")
            
            choice = input("Escolha: ").strip()
            
            if choice == '1':
                self.real_time_monitoring()
            elif choice == '2':
                self.show_full_log()
            elif choice == '3':
                self.clear_log()
            elif choice == '4':
                break
            else:
                print("Opção inválida!")
    
    def show_full_log(self):
        try:
            with open(self.log_file, 'r') as f:
                print("\n=== LOG COMPLETO ===\n")
                for line in f:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            print(f"[{event['timestamp']}] {event['type']}:")
                            print(json.dumps(event['data'], indent=2))
                            print("-" * 50)
                        except json.JSONDecodeError:
                            print(line, end='')
        except FileNotFoundError:
            print("Arquivo de log não encontrado!")
    
    def clear_log(self):
        with open(self.log_file, 'w') as f:
            f.write("=== INÍCIO DO LOG ===\n")
        self.last_position = 0
        print("Log limpo com sucesso!")

if __name__ == "__main__":
    monitor = RSAMonitor()
    monitor.show_menu()