"""
╔══════════════════════════════════════════════════════════════╗
║         🛡️ Cyber Attack Detection API                         ║
║         FastAPI Backend — CICIDS2017 Model                   ║
║         Version: 1.0.0                                       ║
╚══════════════════════════════════════════════════════════════╝

Endpoint utama:
  POST /predict        → Single traffic prediction
  POST /predict/batch  → Batch prediction (maks 1000)
  GET  /model/info     → Info model yang dimuat
  GET  /stats          → Statistik performa model
  GET  /classes        → Daftar semua kelas
  GET  /               → Health check

Cara menjalankan:
  pip install fastapi uvicorn scikit-learn numpy joblib pydantic
  python main.py
  → Swagger UI: http://localhost:8000/docs
"""
import requests
import os
import json
import time
import logging
import numpy as np
import joblib
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import uvicorn

# ============================================================
# SETUP LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("cyber_attack_api")

# ============================================================
# INISIALISASI FASTAPI
# ============================================================
app = FastAPI(
    title="🛡️ Cyber Attack Detection API",
    description="""
## API Deteksi Serangan Jaringan

Menggunakan **Random Forest Classifier** yang ditraining pada dataset **CICIDS2017**.

### Kelas yang Dapat Dideteksi:
| Label | Severity |
|-------|----------|
| BENIGN | none |
| DDoS | critical |
| DoS Hulk | critical |
| DoS GoldenEye | critical |
| DoS Slowloris | high |
| DoS Slowhttptest | high |
| PortScan | low |
| Bot | high |
| FTP-Patator | medium |
| SSH-Patator | medium |
| Web Attack | high |
| Heartbleed | critical |
| Infiltration | critical |

### Cara Penggunaan:
1. Kirim POST request ke `/predict` dengan fitur traffic jaringan
2. API mengembalikan label prediksi, confidence score, dan severity level
3. Gunakan `/predict/batch` untuk analisis banyak traffic sekaligus
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "Cyber Attack Detection Team",
        "email": "admin@example.com"
    }
)

# ============================================================
# CORS MIDDLEWARE
# Izinkan request dari Laravel dan browser
# Ganti allow_origins dengan domain spesifik di produksi
# ============================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ============================================================
# GLOBAL STATE — Model dimuat sekali saat startup
# Variabel global agar bisa diakses di semua endpoint
# ============================================================
MODEL           = None   # Random Forest model
SCALER          = None   # StandardScaler
LABEL_ENCODER   = None   # LabelEncoder (integer ↔ label string)
FEATURE_SELECTOR = None  # SelectKBest feature selector
METADATA        = None   # Info model (JSON)

# Path folder models — bisa di-override via environment variable
# Contoh: export MODELS_DIR=/home/user/models
MODELS_DIR = os.getenv("MODELS_DIR", "./models")

# ============================================================
# SEVERITY COLOR MAP — untuk tampilan UI
# ============================================================
SEVERITY_COLORS = {
    "none":     "#00ff88",   # Hijau  — traffic normal
    "low":      "#00d4ff",   # Biru   — PortScan
    "medium":   "#ffd700",   # Kuning — Brute Force
    "high":     "#ff8c00",   # Oranye — Bot, Web Attack
    "critical": "#ff3860",   # Merah  — DDoS, DoS, Heartbleed
    "unknown":  "#95a5a6",   # Abu    — tidak diketahui
}


# ============================================================
# STARTUP EVENT — Load semua model saat server pertama jalan
# ============================================================
@app.on_event("startup")
async def load_models():
    """
    Load semua artefak ML saat server startup.
    Hanya dilakukan SEKALI untuk efisiensi memori.
    Jika file tidak ditemukan, server tetap jalan tapi
    endpoint predict akan mengembalikan error 503.
    """
    global MODEL, SCALER, LABEL_ENCODER, FEATURE_SELECTOR, METADATA

    logger.info("=" * 60)
    logger.info("🚀 Starting Cyber Attack Detection API...")
    logger.info(f"   Models directory: {MODELS_DIR}")

    # Daftar file yang wajib ada
    required_files = [
        "model.pkl",
        "scaler.pkl",
        "label_encoder.pkl",
        "feature_selector.pkl",
        "model_metadata.json"
    ]

    # Cek semua file ada sebelum load
    missing_files = []
    for f in required_files:
        filepath = os.path.join(MODELS_DIR, f)
        if not os.path.exists(filepath):
            missing_files.append(f)

    if missing_files:
        logger.error(f"❌ File model tidak ditemukan: {missing_files}")
        logger.error("   Jalankan notebook Colab terlebih dahulu!")
        logger.error(f"   Letakkan file .pkl dan .json di folder: {MODELS_DIR}")
        return  # Server tetap jalan, tapi prediksi akan gagal

    try:
        # 1. Load model Random Forest (file terbesar)
        logger.info("   [1/5] Loading model.pkl (Random Forest)...")
        MODEL = joblib.load(os.path.join(MODELS_DIR, "model.pkl"))

        # 2. Load StandardScaler
        logger.info("   [2/5] Loading scaler.pkl...")
        SCALER = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))

        # 3. Load LabelEncoder
        logger.info("   [3/5] Loading label_encoder.pkl...")
        LABEL_ENCODER = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))

        # 4. Load Feature Selector
        logger.info("   [4/5] Loading feature_selector.pkl...")
        FEATURE_SELECTOR = joblib.load(os.path.join(MODELS_DIR, "feature_selector.pkl"))

        # 5. Load metadata (JSON)
        logger.info("   [5/5] Loading model_metadata.json...")
        with open(os.path.join(MODELS_DIR, "model_metadata.json"), "r") as f:
            METADATA = json.load(f)

        # Log ringkasan model yang dimuat
        logger.info("=" * 60)
        logger.info("✅ Semua model berhasil dimuat!")
        logger.info(f"   Model Name  : {METADATA['model_name']}")
        logger.info(f"   Version     : {METADATA['model_version']}")
        logger.info(f"   Classes     : {len(METADATA['classes'])} kelas")
        logger.info(f"   Features    : {METADATA['n_features']} fitur")
        logger.info(f"   Accuracy    : {METADATA['performance']['accuracy']:.4f}")
        logger.info(f"   F1-Score    : {METADATA['performance']['f1_weighted']:.4f}")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"❌ Gagal load model: {e}")
        raise  # Re-raise agar error terlihat di log


# ============================================================
# PYDANTIC MODELS — Skema Input/Output dengan Validasi Otomatis
# Pydantic akan validasi tipe data dan constraint (ge=0, dll)
# sebelum request sampai ke fungsi endpoint
# ============================================================

class NetworkTrafficInput(BaseModel):
    """
    Skema input untuk SATU network traffic flow.

    Fitur sesuai dengan kolom dataset CICIDS2017.
    Fitur wajib: flow_duration, total_fwd_packets, total_bwd_packets.
    Fitur lain punya nilai default 0.0 (opsional).

    Contoh minimal request body:
    {
        "flow_duration": 119366,
        "total_fwd_packets": 2,
        "total_bwd_packets": 0
    }
    """

    # ===== FITUR WAJIB =====
    flow_duration: float = Field(
        ...,
        description="Durasi koneksi dalam microseconds. Wajib diisi.",
        ge=0,
        example=119366.0
    )
    total_fwd_packets: float = Field(
        ...,
        description="Total paket yang dikirim dari source ke destination.",
        ge=0,
        example=2.0
    )
    total_bwd_packets: float = Field(
        ...,
        description="Total paket balasan dari destination ke source.",
        ge=0,
        example=0.0
    )

    # ===== FITUR RATE =====
    flow_bytes_per_s: float      = Field(0.0, ge=0, description="Total byte per detik", example=25.129)
    flow_packets_per_s: float    = Field(0.0, ge=0, description="Total paket per detik", example=16.757)
    fwd_packets_per_s: float     = Field(0.0, ge=0, description="Paket forward per detik")
    bwd_packets_per_s: float     = Field(0.0, ge=0, description="Paket backward per detik")

    # ===== INTER-ARRIVAL TIME (IAT) =====
    # Waktu antar kedatangan paket — penting untuk deteksi Bot dan Slowloris
    flow_iat_mean: float  = Field(0.0, description="Rata-rata IAT seluruh flow", example=119366.0)
    flow_iat_std: float   = Field(0.0, description="Standar deviasi IAT flow")
    flow_iat_max: float   = Field(0.0, description="IAT maksimum dalam flow")
    flow_iat_min: float   = Field(0.0, description="IAT minimum dalam flow")
    fwd_iat_mean: float   = Field(0.0, description="Rata-rata IAT paket forward")
    fwd_iat_std: float    = Field(0.0, description="Standar deviasi IAT forward")
    bwd_iat_mean: float   = Field(0.0, description="Rata-rata IAT paket backward")
    bwd_iat_std: float    = Field(0.0, description="Standar deviasi IAT backward")

    # ===== PACKET LENGTH =====
    # Panjang paket — penting untuk deteksi DDoS dan Web Attack
    packet_length_mean: float     = Field(0.0, ge=0, description="Rata-rata panjang paket (bytes)", example=25.5)
    packet_length_std: float      = Field(0.0, ge=0, description="Standar deviasi panjang paket", example=20.506)
    min_packet_length: float      = Field(0.0, ge=0, description="Panjang paket terkecil")
    max_packet_length: float      = Field(0.0, ge=0, description="Panjang paket terbesar")
    packet_length_variance: float = Field(0.0, ge=0, description="Variansi panjang paket")
    average_packet_size: float    = Field(0.0, ge=0, description="Ukuran rata-rata paket")

    # ===== SEGMENT SIZE =====
    avg_fwd_segment_size: float = Field(0.0, ge=0, description="Rata-rata ukuran segment forward")
    avg_bwd_segment_size: float = Field(0.0, ge=0, description="Rata-rata ukuran segment backward")

    # ===== TCP FLAGS =====
    # Flag TCP — sangat penting untuk deteksi SYN Flood, RST attacks
    fwd_psh_flags: int  = Field(0, ge=0, description="Jumlah flag PSH di paket forward")
    bwd_psh_flags: int  = Field(0, ge=0, description="Jumlah flag PSH di paket backward")
    fwd_urg_flags: int  = Field(0, ge=0, description="Jumlah flag URG di paket forward")
    bwd_urg_flags: int  = Field(0, ge=0, description="Jumlah flag URG di paket backward")
    fin_flag_count: int = Field(0, ge=0, description="Total flag FIN (akhir koneksi)")
    syn_flag_count: int = Field(0, ge=0, description="Total flag SYN (inisiasi koneksi)")
    rst_flag_count: int = Field(0, ge=0, description="Total flag RST (reset koneksi)")
    psh_flag_count: int = Field(0, ge=0, description="Total flag PSH")
    ack_flag_count: int = Field(0, ge=0, description="Total flag ACK (acknowledgement)")
    urg_flag_count: int = Field(0, ge=0, description="Total flag URG (urgent)")
    cwe_flag_count: int = Field(0, ge=0, description="Total flag CWE")
    ece_flag_count: int = Field(0, ge=0, description="Total flag ECE")

    # ===== WINDOW SIZE & MISC =====
    # Initial Window Size — 0 atau sangat kecil bisa indikasi SYN Flood
    init_win_bytes_forward: float  = Field(0.0, description="Ukuran window TCP awal (forward)", example=65535.0)
    init_win_bytes_backward: float = Field(0.0, description="Ukuran window TCP awal (backward)")
    act_data_pkt_fwd: float        = Field(0.0, ge=0, description="Jumlah paket dengan data aktual (forward)")
    min_seg_size_forward: float    = Field(0.0, ge=0, description="Ukuran segment minimum (forward)")
    down_up_ratio: float           = Field(0.0, ge=0, description="Rasio download/upload traffic")

    # ===== ACTIVE/IDLE TIME =====
    # Waktu aktif/idle koneksi — penting untuk deteksi Slowloris
    active_mean: float = Field(0.0, ge=0, description="Rata-rata waktu koneksi aktif")
    active_std: float  = Field(0.0, ge=0, description="Standar deviasi waktu aktif")
    active_max: float  = Field(0.0, ge=0, description="Waktu aktif maksimum")
    active_min: float  = Field(0.0, ge=0, description="Waktu aktif minimum")
    idle_mean: float   = Field(0.0, ge=0, description="Rata-rata waktu koneksi idle")
    idle_std: float    = Field(0.0, ge=0, description="Standar deviasi waktu idle")
    idle_max: float    = Field(0.0, ge=0, description="Waktu idle maksimum")
    idle_min: float    = Field(0.0, ge=0, description="Waktu idle minimum")

    class Config:
        # Contoh request body yang muncul di Swagger UI /docs
        json_schema_extra = {
            "example": {
                "flow_duration": 119366,
                "total_fwd_packets": 2,
                "total_bwd_packets": 0,
                "flow_bytes_per_s": 25.129,
                "flow_packets_per_s": 16.757,
                "flow_iat_mean": 119366.0,
                "packet_length_mean": 25.5,
                "packet_length_std": 20.506,
                "init_win_bytes_forward": 65535.0,
                "syn_flag_count": 1,
                "ack_flag_count": 1,
                "fin_flag_count": 1
            }
        }


class BatchTrafficInput(BaseModel):
    """Schema untuk batch prediction — kirim banyak traffic sekaligus."""
    traffic_flows: List[NetworkTrafficInput]

    @validator("traffic_flows")
    def validate_batch_size(cls, v):
        """Validasi: tidak boleh kosong, maksimal 1000 records."""
        if len(v) == 0:
            raise ValueError("traffic_flows tidak boleh kosong")
        if len(v) > 1000:
            raise ValueError("Maksimal 1000 records per batch request")
        return v


class PredictionResult(BaseModel):
    """Schema output lengkap untuk single prediction."""
    prediction: str               # Label prediksi: "BENIGN", "DDoS", dll
    prediction_id: int            # ID integer label
    confidence: float             # Confidence score: 0.0 - 1.0
    confidence_percent: str       # Confidence dalam format: "98.50%"
    severity_level: str           # none / low / medium / high / critical
    severity_color: str           # Kode warna HEX untuk UI: "#ff3860"
    is_attack: bool               # True jika bukan BENIGN
    all_probabilities: Dict[str, float]   # Probabilitas semua kelas
    top_3_predictions: List[Dict[str, Any]]  # 3 kandidat teratas
    processing_time_ms: float     # Waktu pemrosesan dalam milidetik
    model_version: str            # Versi model yang digunakan


class BatchPredictionResult(BaseModel):
    """Schema output untuk batch prediction."""
    summary: Dict[str, Any]          # Ringkasan statistik
    predictions: List[Dict[str, Any]] # Detail per traffic flow


# ============================================================
# MAPPING: Nama field Pydantic → Nama kolom CICIDS2017
# Diperlukan karena nama kolom dataset menggunakan spasi dan slash
# ============================================================
FIELD_TO_FEATURE_MAP = {
    # Field Pydantic (snake_case)    : Kolom CICIDS2017 (original name)
    "flow_duration":                   "Flow Duration",
    "total_fwd_packets":               "Total Fwd Packets",
    "total_bwd_packets":               "Total Backward Packets",
    "flow_bytes_per_s":                "Flow Bytes/s",
    "flow_packets_per_s":              "Flow Packets/s",
    "fwd_packets_per_s":               "Fwd Packets/s",
    "bwd_packets_per_s":               "Bwd Packets/s",
    "flow_iat_mean":                   "Flow IAT Mean",
    "flow_iat_std":                    "Flow IAT Std",
    "flow_iat_max":                    "Flow IAT Max",
    "flow_iat_min":                    "Flow IAT Min",
    "fwd_iat_mean":                    "Fwd IAT Mean",
    "fwd_iat_std":                     "Fwd IAT Std",
    "bwd_iat_mean":                    "Bwd IAT Mean",
    "bwd_iat_std":                     "Bwd IAT Std",
    "packet_length_mean":              "Packet Length Mean",
    "packet_length_std":               "Packet Length Std",
    "min_packet_length":               "Min Packet Length",
    "max_packet_length":               "Max Packet Length",
    "packet_length_variance":          "Packet Length Variance",
    "average_packet_size":             "Average Packet Size",
    "avg_fwd_segment_size":            "Avg Fwd Segment Size",
    "avg_bwd_segment_size":            "Avg Bwd Segment Size",
    "fwd_psh_flags":                   "Fwd PSH Flags",
    "bwd_psh_flags":                   "Bwd PSH Flags",
    "fwd_urg_flags":                   "Fwd URG Flags",
    "bwd_urg_flags":                   "Bwd URG Flags",
    "fin_flag_count":                  "FIN Flag Count",
    "syn_flag_count":                  "SYN Flag Count",
    "rst_flag_count":                  "RST Flag Count",
    "psh_flag_count":                  "PSH Flag Count",
    "ack_flag_count":                  "ACK Flag Count",
    "urg_flag_count":                  "URG Flag Count",
    "cwe_flag_count":                  "CWE Flag Count",
    "ece_flag_count":                  "ECE Flag Count",
    "init_win_bytes_forward":          "Init_Win_bytes_forward",
    "init_win_bytes_backward":         "Init_Win_bytes_backward",
    "act_data_pkt_fwd":                "act_data_pkt_fwd",
    "min_seg_size_forward":            "min_seg_size_forward",
    "down_up_ratio":                   "Down/Up Ratio",
    "active_mean":                     "Active Mean",
    "active_std":                      "Active Std",
    "active_max":                      "Active Max",
    "active_min":                      "Active Min",
    "idle_mean":                       "Idle Mean",
    "idle_std":                        "Idle Std",
    "idle_max":                        "Idle Max",
    "idle_min":                        "Idle Min",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_severity(label: str) -> str:
    """
    Kembalikan severity level berdasarkan label prediksi.

    Priority: pakai metadata dari model jika ada,
    fallback ke hardcoded mapping.
    """
    # Coba ambil dari metadata dulu
    if METADATA and "severity_levels" in METADATA:
        return METADATA["severity_levels"].get(label, "medium")

    # Fallback hardcoded mapping
    severity_map = {
        "BENIGN":            "none",
        "DDoS":              "critical",
        "DoS Hulk":          "critical",
        "DoS GoldenEye":     "critical",
        "DoS Slowloris":     "high",
        "DoS Slowhttptest":  "high",
        "PortScan":          "low",
        "Bot":               "high",
        "FTP-Patator":       "medium",
        "SSH-Patator":       "medium",
        "Web Attack":        "high",
        "Heartbleed":        "critical",
        "Infiltration":      "critical",
    }
    return severity_map.get(label, "medium")


def preprocess_input(traffic: NetworkTrafficInput) -> np.ndarray:
    """
    Konversi objek NetworkTrafficInput menjadi numpy array
    dengan urutan fitur yang TEPAT sama seperti saat training.

    Langkah preprocessing:
    1. Map nama field Pydantic → nama kolom dataset CICIDS2017
    2. Susun array sesuai urutan selected_feature_names dari metadata
    3. Handle nilai NaN dan Infinity (ganti dengan 0 atau nilai batas)

    Returns:
        np.ndarray shape (1, n_features) — siap untuk model.predict()
    """
    if METADATA is None:
        raise HTTPException(
            status_code=503,
            detail="Model metadata tidak tersedia. Pastikan model_metadata.json ada."
        )

    # Konversi objek Pydantic ke dict Python biasa
    traffic_dict = traffic.dict()

    # Map semua field ke nama kolom dataset
    feature_dict = {}
    for pydantic_field, dataset_col in FIELD_TO_FEATURE_MAP.items():
        value = traffic_dict.get(pydantic_field, 0.0)
        # Pastikan tipe float (bukan None)
        feature_dict[dataset_col] = float(value) if value is not None else 0.0

    # Susun array SESUAI URUTAN fitur saat training
    # Urutan ini disimpan di metadata['feature_names']
    feature_names = METADATA["feature_names"]  # list of 30 selected features
    feature_vector = []
    for fname in feature_names:
        val = feature_dict.get(fname, 0.0)
        feature_vector.append(val)

    # Konversi ke numpy array
    arr = np.array(feature_vector, dtype=np.float64).reshape(1, -1)

    # Bersihkan nilai tidak valid
    # nan → 0.0 (tidak ada informasi)
    # +inf → 1e10 (batas atas yang masih bisa diproses)
    # -inf → 0.0
    arr = np.nan_to_num(arr, nan=0.0, posinf=1e10, neginf=0.0)

    return arr  # shape: (1, n_features)


def check_model_loaded():
    """
    Cek apakah semua komponen model sudah dimuat.
    Raise HTTPException 503 jika belum siap.
    """
    if MODEL is None or LABEL_ENCODER is None or METADATA is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Model belum siap",
                "message": "Pastikan file model.pkl, scaler.pkl, label_encoder.pkl, "
                          "feature_selector.pkl, dan model_metadata.json ada di folder models/",
                "models_dir": MODELS_DIR
            }
        )


# ============================================================
# GLOBAL EXCEPTION HANDLER
# Tangkap semua error yang tidak tertangani
# ============================================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handler untuk error tak terduga — kembalikan JSON yang rapi."""
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "path": str(request.url)
        }
    )


# ============================================================
# ENDPOINT 1: Health Check
# ============================================================
@app.get(
    "/",
    tags=["Health"],
    summary="Health Check — Cek status API"
)
def root():
    """
    **Health check endpoint.**

    Gunakan endpoint ini untuk:
    - Memverifikasi server berjalan
    - Cek apakah model sudah dimuat
    - Mendapatkan daftar endpoint yang tersedia

    Response `model_loaded: false` berarti model belum bisa digunakan.
    """
    return {
        "status": "running",
        "service": "Cyber Attack Detection API",
        "version": "1.0.0",
        "model_loaded": MODEL is not None,
        "model_name": METADATA["model_name"] if METADATA else None,
        "n_classes": len(METADATA["classes"]) if METADATA else 0,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "endpoints": {
            "health_check":     "GET  /",
            "swagger_docs":     "GET  /docs",
            "predict_single":   "POST /predict",
            "predict_batch":    "POST /predict/batch",
            "model_info":       "GET  /model/info",
            "statistics":       "GET  /stats",
            "classes":          "GET  /classes"
        }
    }


# ============================================================
# ENDPOINT 2: Model Info
# ============================================================
@app.get(
    "/model/info",
    tags=["Model"],
    summary="Informasi detail model ML"
)
def model_info():
    """
    **Informasi lengkap tentang model yang sedang digunakan.**

    Mengembalikan:
    - Nama dan versi model
    - Tanggal training
    - Daftar fitur yang digunakan
    - Daftar kelas yang dapat dideteksi
    - Metrik performa dari training (accuracy, F1, dll)
    - Mapping severity per kelas
    """
    check_model_loaded()

    return {
        "model_name":     METADATA["model_name"],
        "model_version":  METADATA["model_version"],
        "created_at":     METADATA["created_at"],
        "dataset":        METADATA["dataset"],
        "n_features":     METADATA["n_features"],
        "feature_names":  METADATA["feature_names"],
        "classes":        METADATA["classes"],
        "n_classes":      METADATA["n_classes"],
        "performance":    METADATA["performance"],
        "severity_levels": METADATA["severity_levels"]
    }


# ============================================================
# ENDPOINT 3: Single Prediction (ENDPOINT UTAMA)
# ============================================================
@app.post(
    "/predict",
    response_model=PredictionResult,
    tags=["Prediction"],
    summary="Prediksi satu traffic flow jaringan"
)
def predict(traffic: NetworkTrafficInput):
    """
    **Prediksi jenis traffic jaringan (satu flow).**

    Ini adalah endpoint utama. Kirim fitur satu koneksi jaringan
    dan dapatkan klasifikasi apakah itu serangan atau traffic normal.

    ### Input Wajib
    - `flow_duration` — durasi koneksi (microseconds)
    - `total_fwd_packets` — jumlah paket yang dikirim
    - `total_bwd_packets` — jumlah paket yang diterima

    ### Output
    - `prediction` — label kelas: "BENIGN", "DDoS", "Bot", dll
    - `confidence` — keyakinan model (0.0 - 1.0, makin tinggi makin yakin)
    - `severity_level` — tingkat bahaya: none/low/medium/high/critical
    - `severity_color` — warna HEX untuk tampilan UI
    - `is_attack` — True jika bukan BENIGN
    - `all_probabilities` — probabilitas untuk semua kelas
    - `top_3_predictions` — 3 kandidat prediksi teratas
    - `processing_time_ms` — waktu pemrosesan

    ### Contoh (curl)
```bash
    curl -X POST http://localhost:8000/predict \\
      -H "Content-Type: application/json" \\
      -d '{
        "flow_duration": 119366,
        "total_fwd_packets": 2,
        "total_bwd_packets": 0,
        "flow_bytes_per_s": 25.129,
        "flow_packets_per_s": 16.757,
        "init_win_bytes_forward": 65535
      }'
```
    """
    check_model_loaded()

    start_time = time.perf_counter()

    try:
        # ----- STEP 1: Preprocessing -----
        # Konversi input JSON → numpy array sesuai format training
        X = preprocess_input(traffic)

        # ----- STEP 2: Prediksi -----
        # predict() → label integer [0, 1, 2, ...]
        # predict_proba() → array probabilitas semua kelas
        pred_id = int(MODEL.predict(X)[0])
        proba   = MODEL.predict_proba(X)[0]  # shape: (n_classes,)

        # ----- STEP 3: Decode Label -----
        # LabelEncoder.inverse_transform: integer → string label
        pred_label = LABEL_ENCODER.inverse_transform([pred_id])[0]
        confidence = float(proba[pred_id])

        # ----- STEP 4: Susun Probabilitas Semua Kelas -----
        all_proba = {
            LABEL_ENCODER.classes_[i]: round(float(p), 6)
            for i, p in enumerate(proba)
        }

        # ----- STEP 5: Top 3 Prediksi -----
        # argsort descending → ambil 3 indeks dengan probabilitas tertinggi
        top3_idx = np.argsort(proba)[::-1][:3]
        top3 = [
            {
                "rank": i + 1,
                "label": LABEL_ENCODER.classes_[idx],
                "confidence": round(float(proba[idx]), 6),
                "confidence_percent": f"{proba[idx] * 100:.2f}%",
                "severity": get_severity(LABEL_ENCODER.classes_[idx])
            }
            for i, idx in enumerate(top3_idx)
        ]

        # ----- STEP 6: Severity & Warna -----
        severity       = get_severity(pred_label)
        severity_color = SEVERITY_COLORS.get(severity, "#95a5a6")

        # ----- STEP 7: Hitung Waktu Pemrosesan -----
        processing_ms = (time.perf_counter() - start_time) * 1000

        # ----- STEP 8: Log Jika Serangan -----
        if pred_label != "BENIGN":
            logger.warning(
                f"🚨 ATTACK DETECTED | Type: {pred_label} | "
                f"Severity: {severity.upper()} | "
                f"Confidence: {confidence:.4f} ({confidence*100:.1f}%)"
            )
        else:
            logger.info(
                f"✅ BENIGN traffic | "
                f"Confidence: {confidence:.4f} | "
                f"Time: {processing_ms:.1f}ms"
            )

        # ----- RETURN RESPONSE -----
        return PredictionResult(
            prediction=pred_label,
            prediction_id=pred_id,
            confidence=confidence,
            confidence_percent=f"{confidence * 100:.2f}%",
            severity_level=severity,
            severity_color=severity_color,
            is_attack=(pred_label != "BENIGN"),
            all_probabilities=all_proba,
            top_3_predictions=top3,
            processing_time_ms=round(processing_ms, 3),
            model_version=METADATA.get("model_version", "1.0.0")
        )

    except HTTPException:
        raise  # Re-raise tanpa wrap ulang

    except Exception as e:
        logger.error(f"Prediction error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Prediction failed",
                "detail": str(e)
            }
        )


# ============================================================
# ENDPOINT 4: Batch Prediction
# ============================================================
@app.post(
    "/predict/batch",
    response_model=BatchPredictionResult,
    tags=["Prediction"],
    summary="Prediksi banyak traffic flow sekaligus (batch)"
)
def predict_batch(batch: BatchTrafficInput):
    """
    **Prediksi banyak traffic flow sekaligus.**

    Berguna untuk menganalisis log jaringan secara massal.
    Kirim array `traffic_flows` berisi hingga **1000 records**.

    ### Output Summary
    - `total_processed` — jumlah record yang diproses
    - `attack_count` — jumlah yang terdeteksi sebagai serangan
    - `benign_count` — jumlah traffic normal
    - `attack_rate` — persentase serangan
    - `severity_distribution` — distribusi severity level
    - `attack_type_distribution` — distribusi jenis serangan
    - `processing_time_ms` — total waktu pemrosesan

    ### Contoh (curl)
```bash
    curl -X POST http://localhost:8000/predict/batch \\
      -H "Content-Type: application/json" \\
      -d '{
        "traffic_flows": [
          {"flow_duration": 119366, "total_fwd_packets": 2, "total_bwd_packets": 0},
          {"flow_duration": 988,    "total_fwd_packets": 1, "total_bwd_packets": 0,
           "flow_bytes_per_s": 12146.1, "flow_packets_per_s": 1012.1}
        ]
      }'
```
    """
    check_model_loaded()

    start_time = time.perf_counter()

    predictions          = []
    attack_count         = 0
    errors               = 0
    severity_counts:     Dict[str, int] = {}
    attack_type_counts:  Dict[str, int] = {}

    for i, traffic in enumerate(batch.traffic_flows):
        try:
            # Preprocess dan predict
            X          = preprocess_input(traffic)
            pred_id    = int(MODEL.predict(X)[0])
            proba      = MODEL.predict_proba(X)[0]
            pred_label = LABEL_ENCODER.inverse_transform([pred_id])[0]
            confidence = float(proba[pred_id])
            severity   = get_severity(pred_label)
            is_attack  = pred_label != "BENIGN"

            # Simpan hasil per record
            predictions.append({
                "index":              i,
                "prediction":         pred_label,
                "prediction_id":      pred_id,
                "confidence":         round(confidence, 4),
                "confidence_percent": f"{confidence * 100:.1f}%",
                "severity_level":     severity,
                "severity_color":     SEVERITY_COLORS.get(severity, "#95a5a6"),
                "is_attack":          is_attack
            })

            # Akumulasi statistik
            if is_attack:
                attack_count += 1
                attack_type_counts[pred_label] = attack_type_counts.get(pred_label, 0) + 1

            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        except Exception as e:
            # Jangan hentikan seluruh batch karena satu error
            logger.warning(f"Error on batch index {i}: {e}")
            predictions.append({
                "index":      i,
                "error":      str(e),
                "prediction": "ERROR",
                "is_attack":  False
            })
            errors += 1

    # Hitung ringkasan
    total         = len(batch.traffic_flows)
    processing_ms = (time.perf_counter() - start_time) * 1000
    benign_count  = total - attack_count - errors

    logger.info(
        f"Batch completed: {total} flows | "
        f"{attack_count} attacks | "
        f"{benign_count} benign | "
        f"{errors} errors | "
        f"{processing_ms:.1f}ms"
    )

    return BatchPredictionResult(
        summary={
            "total_processed":          total,
            "attack_count":             attack_count,
            "benign_count":             benign_count,
            "error_count":              errors,
            "attack_rate":              f"{(attack_count / total * 100):.1f}%" if total > 0 else "0%",
            "severity_distribution":    severity_counts,
            "attack_type_distribution": dict(
                sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)
            ),
            "processing_time_ms":       round(processing_ms, 2),
            "avg_time_per_record_ms":   round(processing_ms / total, 2) if total > 0 else 0
        },
        predictions=predictions
    )


# ============================================================
# ENDPOINT 5: Statistics
# ============================================================
@app.get(
    "/stats",
    tags=["Statistics"],
    summary="Statistik performa model dari training"
)
def get_stats():
    """
    **Statistik performa model.**

    Mengembalikan metrik evaluasi yang dihitung saat training:
    - Accuracy, Precision, Recall, F1-Score (weighted)
    - Info dataset dan jumlah fitur/kelas
    - Mapping severity per kelas
    """
    check_model_loaded()

    perf = METADATA.get("performance", {})

    return {
        "model_performance": {
            "accuracy":            perf.get("accuracy", 0),
            "accuracy_percent":    f"{perf.get('accuracy', 0) * 100:.2f}%",
            "f1_weighted":         perf.get("f1_weighted", 0),
            "precision_weighted":  perf.get("precision_weighted", 0),
            "recall_weighted":     perf.get("recall_weighted", 0),
        },
        "model_info": {
            "name":       METADATA.get("model_name"),
            "version":    METADATA.get("model_version"),
            "dataset":    METADATA.get("dataset"),
            "n_features": METADATA.get("n_features"),
            "n_classes":  METADATA.get("n_classes"),
            "created_at": METADATA.get("created_at"),
        },
        "classes":         METADATA.get("classes", []),
        "severity_levels": METADATA.get("severity_levels", {}),
    }


# ============================================================
# ENDPOINT 6: Classes
# ============================================================
@app.get(
    "/classes",
    tags=["Model"],
    summary="Daftar semua kelas yang dapat dideteksi"
)
def get_classes():
    """
    **Daftar kelas serangan beserta detail severity.**

    Berguna untuk membangun UI dropdown atau legenda chart di frontend.
    """
    check_model_loaded()

    classes_info = []
    for cls in METADATA.get("classes", []):
        severity = get_severity(cls)
        classes_info.append({
            "label":         cls,
            "label_id":      int(list(LABEL_ENCODER.classes_).index(cls)),
            "is_attack":     cls != "BENIGN",
            "severity":      severity,
            "severity_color": SEVERITY_COLORS.get(severity, "#95a5a6"),
        })

    return {
        "total_classes": len(classes_info),
        "classes":       classes_info
    }

# Endpoint Webhook Baru untuk menangkap Live Packet Sniffer
@app.post("/predict/live", tags=["Prediction Summary"])
def predict_live_traffic(traffic: NetworkTrafficInput):
    check_model_loaded()
    
    # 1. Jalankan prediksi AI menggunakan model Random Forest internal
    X = preprocess_input(traffic)
    pred_id = int(MODEL.predict(X)[0])
    proba = MODEL.predict_proba(X)[0]
    pred_label = LABEL_ENCODER.inverse_transform([pred_id])[0]
    confidence = float(proba[pred_id])
    severity = get_severity(pred_label)
    
    ai_result = {
        "status": "success",
        "prediction": pred_label,
        "confidence": round(confidence, 4),
        "confidence_percent": f"{confidence * 100:.2f}%",
        "severity_level": severity,
        "is_attack": pred_label != "BENIGN"
    }
    
    # 2. Forward/Lemparkan hasil prediksi AI langsung ke Webhook Laravel secara otomatis
    LARAVEL_WEBHOOK_URL = "http://127.0.0.1:8001/webhook/live-traffic"
    
    # Satukan data input sniffer dan hasil prediksi kecerdasan buatan
    payload_to_laravel = {
        "features": traffic.dict(),
        "result": ai_result
    }
    
    try:
        # Tembak API Laravel di port 8001
        requests.post(LARAVEL_WEBHOOK_URL, json=payload_to_laravel, timeout=1)
    except Exception as e:
        logger.error(f"Gagal mengirimkan log live ke Webhook Laravel: {e}")
        
    return ai_result

# ============================================================
# ENTRY POINT — Jalankan dengan: python main.py
# ============================================================
if __name__ == "__main__":
    print()
    print("=" * 55)
    print("  🛡️  Cyber Attack Detection API")
    print("=" * 55)
    print(f"  Models dir  : {MODELS_DIR}")
    print(f"  Server      : http://0.0.0.0:8000")
    print(f"  Swagger UI  : http://localhost:8000/docs")
    print(f"  ReDoc       : http://localhost:8000/redoc")
    print(f"  Health      : http://localhost:8000/")
    print()
    print("  Endpoints:")
    print("    POST /predict         → Single prediction")
    print("    POST /predict/batch   → Batch prediction")
    print("    GET  /model/info      → Model information")
    print("    GET  /stats           → Performance stats")
    print("    GET  /classes         → Available classes")
    print("=" * 55)
    print()

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,        # Hot reload — restart otomatis saat file berubah
        log_level="info",
        access_log=True     # Log setiap request masuk
    )