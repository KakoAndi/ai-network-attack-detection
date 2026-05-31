import time
import requests
from scapy.all import sniff, IP, TCP

# URL Webhook FastAPI (Menunjuk ke server uvicorn lokalmu)
FASTAPI_WEBHOOK_URL = "http://127.0.0.1:8000/predict/live"

print("🛡️  Live Packet Sniffer Active... Mengendus traffic jaringan lokal.")

# Kamus sementara untuk menghitung statistik per percakapan (flow)
flow_tracker = {}

def process_packet(packet):
    # Hanya memproses paket yang memiliki protokol IP dan TCP
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        # Bikin kunci unik berdasarkan IP dan Port (Source -> Destination)
        flow_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:{tcp_layer.dport}"
        current_time = time.time()
        
        # Ekstraksi fitur statistik esensial ala CICIDS2017 secara real-time
        if flow_key not in flow_tracker:
            flow_tracker[flow_key] = {
                "start_time": current_time,
                "fwd_packets": 1,
                "fwd_lengths": [len(packet)],
                "last_packet_time": current_time,
                "iat_values": []
            }
        else:
            flow = flow_tracker[flow_key]
            flow["fwd_packets"] += 1
            flow["fwd_lengths"].append(len(packet))
            flow["iat_values"].append((current_time - flow["last_packet_time"]) * 1000000) # konversi ke mikrodetik
            flow["last_packet_time"] = current_time
            
            # Jika paket dalam satu percakapan sudah terkumpul cukup (misal 5 paket), kirim ke AI
            if flow["fwd_packets"] >= 5:
                duration = (current_time - flow["start_time"]) * 1000000
                avg_iat = sum(flow["iat_values"]) / len(flow["iat_values"]) if flow["iat_values"] else 0
                max_len = max(flow["fwd_lengths"])
                mean_len = sum(flow["fwd_lengths"]) / len(flow["fwd_lengths"])
                
                # Susun struktur payload 10-fitur utama simulator
                payload = {
                    "destination_port": int(tcp_layer.dport),
                    "flow_duration": float(max(duration, 1.0)),
                    "total_fwd_packets": float(flow["fwd_packets"]),
                    "total_bwd_packets": 3.0, # Dummy backward packet karena sniffer ini single-direction
                    "fwd_packet_length_max": float(max_len),
                    "bwd_packet_length_std": "45.2", # Dikirim string desimal standar agar aman di validasi laravel
                    "flow_iat_mean": float(avg_iat),
                    "fwd_header_length": int(flow["fwd_packets"] * 20),
                    "packet_length_mean": float(mean_len),
                    "fwd_psh_flags": 1 if 'P' in str(tcp_layer.flags) else 0
                }
                
                # Kirim data secara asinkron lewat Webhook ke FastAPI Engine
                try:
                    response = requests.post(FASTAPI_WEBHOOK_URL, json=payload, timeout=1)
                    if response.status_code == 200:
                        res_data = response.json()
                        status_label = "🚨 ATTACK" if res_data.get("is_attack") else "🟢 BENIGN"
                        print(f"[{status_label}] Port: {payload['destination_port']} | Conf: {res_data.get('confidence_percent')}")
                except Exception as e:
                    pass
                
                # Reset flow setelah dikirim agar memory tidak bengkak
                del flow_tracker[flow_key]

# Jalankan pengendusan tak terbatas (Sniffing loop)
sniff(filter="ip and tcp", prn=process_packet, store=0)