# 🛡️ AI-Powered Network Intrusion Detection System (NIDS) Dashboard

[![Laravel Version](https://img.shields.io/badge/Laravel-11.x-red.svg)](https://laravel.com)
[![FastAPI Version](https://img.shields.io/badge/FastAPI-v0.100+-emerald.svg)](https://fastapi.tiangolo.com)
[![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![ML Model](https://img.shields.io/badge/Model-Random%20Forest-indigo.svg)]()
[![Dataset](https://img.shields.io/badge/Dataset-CICIDS2017-orange.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)

Sistem Deteksi Intrusi Jaringan (NIDS) berskala Enterprise yang mengintegrasikan kapabilitas **Machine Learning (Random Forest)** untuk klasifikasi ancaman siber secara *real-time* dengan antarmuka **Security Operations Center (SOC) Dashboard** yang interaktif. 

Sistem ini mengadopsi arsitektur *decoupled services* untuk memisahkan beban komputasi analitik AI dengan manajemen data aplikasi.

---

## 🚀 Fitur Utama (Core Features)

* **Real-Time Machine Learning Inference:** Integrasi model Random Forest Classifier cerdas yang dilatih menggunakan dataset standar industri **CICIDS2017** untuk mendeteksi 13 jenis kategori traffic dan serangan siber.
* **Live Packet Capturing (PCAP) via Webhook:** Menggunakan skrip *network sniffer* berbasis `Scapy` di latar belakang sistem untuk mengendus paket TCP/IP riil langsung dari kartu jaringan (NIC), mengekstrak fiturnya, dan mengevaluasinya secara otomatis.
* **Geospatial Cyber Threat Intelligence:** Visualisasi peta dunia interaktif (*Dark-Themed Map*) menggunakan `Leaflet.js` untuk memetakan koordinat geolocation asal serangan siber secara geografis dengan efek animasi pulsa (*ping effect*).
* **Advanced SOC Analytics:** Grafik pemantauan tren volume traffic (24 Jam) dan diagram distribusi kategori intrusi menggunakan `ApexCharts`.
* **Model Performance Evaluation Component:** Menyediakan bagan komparasi performa evaluasi (Accuracy, Precision, Recall, F1-Score) antara Random Forest, Decision Tree, dan Logistic Regression berdasarkan hasil riset laboratorium.
* **Incident Simulator:** Modul simulator input 10-fitur jaringan esensial untuk keperluan pengujian validasi skema dan demonstrasi taktis.

---

## 🏗️ Arsitektur Sistem (System Architecture)

Sistem ini terbagi menjadi tiga komponen utama yang saling berinteraksi secara asinkron lewat Webhook API:

1.  **Frontend & Log Engine (Laravel 11 & MySQL):** Berjalan pada port `8001`, berfungsi mengelola visualisasi dashboard, memproses data spasial, dan mengamankan rekaman transaksi log ke database.
2.  **AI Analitikal Engine (FastAPI):** Berjalan pada port `8000`, memuat artefak ML (`model.pkl`, `scaler.pkl`, `label_encoder.pkl`), serta menyediakan endpoint berkinerja tinggi untuk standarisasi skala dan inferensi data.
3.  **Network Interceptor (Python Sniffer):** Berjalan di latar belakang, menangkap traffic interface jaringan lokal, menyusun bentuk statistik *network flow*, dan mengalirkannya ke AI Engine.

---

## 🛠️ Panduan Instalasi (Installation Setup)

### 1. Prasyarat Sistem (Prerequisites)
* PHP >= 8.2 & Composer
* MySQL / MariaDB
* Python >= 3.10
* Driver **Npcap** (Wajib untuk Windows pengguna guna mengaktifkan fungsi Scapy Packet Sniffing)

### 2. Konfigurasi Backend AI & Sniffer (FastAPI)
```bash
# Masuk ke direktori projek Python
cd fastapi-attack-detection

# Aktifkan Virtual Environment
venv\Scripts\activate

# Install dependensi library
pip install fastapi uvicorn scikit-learn numpy joblib pydantic scapy requests

# Pastikan file model (.pkl) dan model_metadata.json sudah berada di dalam folder /models

# Jalankan server FastAPI
python main.py 
