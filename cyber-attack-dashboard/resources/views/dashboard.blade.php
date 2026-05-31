<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Attack Detection Dashboard</title>
    
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
    
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    
    <style>
        /* Memaksa kontainer Leaflet Map memiliki tinggi mutlak dan tidak rusak */
        #map { 
            height: 400px !important; 
            width: 100% !important;
        }
        .leaflet-control-container {
            z-index: 10 !important;
        }
    </style>
</head>
<body class="bg-slate-900 text-slate-100 font-sans">

    <div class="container mx-auto p-6">
        
        <div class="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
            <div>
                <h1 class="text-3xl font-bold tracking-tight text-white">🛡️ Cyber Attack NIDS Dashboard</h1>
                <p class="text-slate-400 text-sm">Framework Laravel 11 dengan Integrasi Model Random Forest (CICIDS2017)</p>
            </div>
            <div>
                @if($apiStatus)
                    <span class="inline-flex items-center gap-1.5 py-1.5 px-3 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span> ML Engine Online
                    </span>
                @else
                    <span class="inline-flex items-center gap-1.5 py-1.5 px-3 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        <span class="h-2 w-2 rounded-full bg-rose-400"></span> ML Engine Offline
                    </span>
                @endif
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <p class="text-sm font-medium text-slate-400">Total Traffic Dianalisis</p>
                <p class="text-3xl font-bold text-white mt-2">{{ number_format($totalAnalyzed) }}</p>
            </div>
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <p class="text-sm font-medium text-slate-400">Serangan Terdeteksi</p>
                <p class="text-3xl font-bold text-rose-500 mt-2">{{ number_format($totalAttacks) }}</p>
            </div>
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <p class="text-sm font-medium text-slate-400">Rasio Serangan (Attack Rate)</p>
                <p class="text-3xl font-bold text-amber-500 mt-2">{{ number_format($attackRate, 2) }}%</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 lg:col-span-2">
                <h3 class="text-lg font-bold text-white mb-4">📈 Real-Time Monitoring & Trend Traffic (24 Jam)</h3>
                <div id="trafficLineChart"></div>
            </div>
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <h3 class="text-lg font-bold text-white mb-4">🥧 Distribusi Kategori Traffic</h3>
                <div id="attackPieChart"></div>
            </div>
        </div>

        <div class="grid grid-cols-1 gap-6 mb-8">
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <h3 class="text-lg font-bold text-white mb-1">🗺️ Real-Time Cyber Threat Geolocation Map</h3>
                <p class="text-slate-400 text-xs mb-4">Peta sebaran global serangan siber yang berhasil diinterseptor oleh arsitektur model Random Forest.</p>
                
                <div id="map" class="w-full h-[400px] rounded-lg border border-slate-900 bg-slate-950"></div>
            </div>
        </div>

        <div class="grid grid-cols-1 gap-6 mb-8 mt-6">
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <h3 class="text-lg font-bold text-white mb-2">📊 Evaluasi & Komparasi Performa Model ML</h3>
                <p class="text-slate-400 text-xs mb-4">Perbandingan performa Random Forest vs Decision Tree vs Logistic Regression berdasarkan dataset CICIDS2017.</p>
                <div id="modelComparisonBarChart"></div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <h3 class="text-lg font-bold text-white mb-4">📱 Simulator Input Traffic Jaringan</h3>
                
                @if ($errors->any())
                    <div class="mb-4 p-4 rounded-lg bg-rose-500/20 border border-rose-500/30 text-rose-300 text-xs">
                        <p class="font-bold mb-1">❌ Gagal Memproses Input:</p>
                        <ul class="list-disc list-inside space-y-1">
                            @foreach ($errors->all() as $error)
                                <li>{{ $error }}</li>
                            @endforeach
                        </ul>
                    </div>
                @endif

                @if (session('error'))
                    <div class="mb-4 p-4 rounded-lg bg-amber-500/20 border border-amber-500/30 text-amber-300 text-xs">
                        <p class="font-bold">⚠️ Masalah Sistem:</p>
                        <p>{{ session('error') }}</p>
                    </div>
                @endif

                @if(session('success_prediction'))
                    <div class="mb-4 p-4 rounded-lg {{ session('success_prediction.is_attack') ? 'bg-rose-500/20 border border-rose-500/30 text-rose-300' : 'bg-emerald-500/20 border border-emerald-500/30 text-emerald-300' }}">
                        <p class="font-bold">Hasil Prediksi Engine:</p>
                        <p class="text-2xl font-black my-1">{{ session('success_prediction.prediction') }}</p>
                        <p class="text-xs">Confidence Score: {{ session('success_prediction.confidence_percent') }} | Severity: <span class="underline font-bold">{{ session('success_prediction.severity_level') }}</span></p>
                    </div>
                @endif

                <form action="{{ route('traffic.analyze') }}" method="POST" class="space-y-3 text-slate-300">
                    @csrf
                    <div>
                        <label class="text-xs font-semibold block mb-1">Destination Port</label>
                        <input type="number" name="destination_port" value="80" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                    </div>
                    <div>
                        <label class="text-xs font-semibold block mb-1">Flow Duration (μs)</label>
                        <input type="number" name="flow_duration" value="45000" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                    </div>
                    <div class="grid grid-cols-2 gap-2">
                        <div>
                            <label class="text-xs font-semibold block mb-1">Total Fwd Packets</label>
                            <input type="number" name="total_fwd_packets" value="5" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                        </div>
                        <div>
                            <label class="text-xs font-semibold block mb-1">Total Bwd Packets</label>
                            <input type="number" name="total_bwd_packets" value="3" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-2">
                        <div>
                            <label class="text-xs font-semibold block mb-1">Fwd Pkt Length Max</label>
                            <input type="number" step="any" name="fwd_packet_length_max" value="120" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                        </div>
                        <div>
                            <label class="text-xs font-semibold block mb-1">Bwd Pkt Length Std</label>
                            <input type="number" step="any" name="bwd_packet_length_std" value="45.2" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                        </div>
                    </div>
                    <div>
                        <label class="text-xs font-semibold block mb-1">Flow IAT Mean</label>
                        <input type="number" step="any" name="flow_iat_mean" value="1500" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                    </div>
                    <div>
                        <label class="text-xs font-semibold block mb-1">Fwd Header Length</label>
                        <input type="number" name="fwd_header_length" value="100" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                    </div>
                    <div>
                        <label class="text-xs font-semibold block mb-1">Packet Length Mean</label>
                        <input type="number" step="any" name="packet_length_mean" value="85" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                    </div>
                    <div>
                        <label class="text-xs font-semibold block mb-1">Fwd PSH Flags (Count)</label>
                        <input type="number" name="fwd_psh_flags" value="0" class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-sm text-white" required>
                    </div>
                    <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 px-4 rounded text-sm transition">
                        ⚡ Jalankan Inferensi Model
                    </button>
                </form>
            </div>

            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 lg:col-span-2">
                <h3 class="text-lg font-bold text-white mb-4">📋 Log Aktivitas Traffic Terbaru</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm text-slate-300">
                        <thead class="bg-slate-900 text-xs uppercase text-slate-400 border-b border-slate-700">
                            <tr>
                                <th class="p-3">Waktu</th>
                                <th class="p-3">Port Target</th>
                                <th class="p-3">Klasifikasi</th>
                                <th class="p-3">Confidence</th>
                                <th class="p-3">Severity</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-700/50">
                            @forelse($recentLogs as $log)
                                <tr class="hover:bg-slate-700/30 transition">
                                    <td class="p-3 text-slate-400">{{ $log->detected_at }}</td>
                                    <td class="p-3 font-mono">{{ $log->destination_port }}</td>
                                    <td class="p-3">
                                        <span class="font-bold {{ $log->is_attack ? 'text-rose-400' : 'text-emerald-400' }}">
                                            {{ $log->prediction }}
                                        </span>
                                    </td>
                                    <td class="p-3 font-mono">{{ number_format($log->confidence * 100, 2) }}%</td>
                                    <td class="p-3">
                                        @if($log->severity_level === 'critical' || $log->severity_level === 'high' || $log->severity_level === 'HIGH')
                                            <span class="px-2 py-0.5 rounded text-xs bg-rose-500/20 text-rose-400 font-bold border border-rose-500/20">HIGH</span>
                                        @elseif($log->severity_level === 'medium' || $log->severity_level === 'MEDIUM')
                                            <span class="px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-400 font-bold border border-amber-500/20">MED</span>
                                        @else
                                            <span class="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-400 font-medium border border-emerald-500/20">NONE</span>
                                        @endif
                                    </td>
                                </tr>
                            @empty
                                <tr>
                                    <td colspan="5" class="p-4 text-center text-slate-500">Belum ada data traffic masuk.</td>
                                </tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        // 1. Data Parsing dari Blade Directive ke Vanilla JS Object
        const pieData = @json($attackDistribution);
        const lineData = @json($hourlyTraffic);

        // --- INISIALISASI PIE CHART (DISTRIBUSI ATTACK) ---
        const pieOptions = {
            chart: { type: 'donut', height: 320 },
            series: pieData.map(item => item.value),
            labels: pieData.map(item => item.label),
            theme: { palette: 'palette1' },
            legend: { position: 'bottom', labels: { colors: '#94a3b8' } },
            stroke: { show: false }
        };
        new ApexCharts(document.querySelector("#attackPieChart"), pieOptions).render();

        // --- INISIALISASI LINE CHART (TRAFFIC MONITORING TRENDS) ---
        const lineOptions = {
            chart: { type: 'line', height: 300, toolbar: { show: false } },
            stroke: { curve: 'smooth', width: 3 },
            colors: ['#38bdf8', '#f43f5e'],
            series: [
                { name: 'Total Traffic', data: lineData.map(item => item.total) },
                { name: 'Intrusi / Serangan', data: lineData.map(item => item.attacks) }
            ],
            xaxis: {
                categories: lineData.map(item => item.hour),
                labels: { style: { colors: '#94a3b8' } }
            },
            yaxis: { labels: { style: { colors: '#94a3b8' } } },
            legend: { labels: { colors: '#94a3b8' } },
            grid: { borderColor: '#334155' }
        };
        new ApexCharts(document.querySelector("#trafficLineChart"), lineOptions).render();

        // --- INISIALISASI LEAFLET.JS GEOLOCATION THREAT MAP ---
        const map = L.map('map').setView([25.0, 30.0], 2); // Set view dunia seimbang

        // Load ubin peta dunia bergaya gelap (CartoDB Dark Matter)
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 20
        }).addTo(map);

        const attackLocations = @json($attackLocations);

        // Desain ikon marker khusus berwarna merah pulsa menyala (CSS Pulse Ping)
        const attackIcon = L.divIcon({
            className: 'custom-icon',
            html: `<div class="relative flex h-4 w-4">
                     <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                     <span class="relative inline-flex rounded-full h-4 w-4 bg-rose-600 border border-white"></span>
                   </div>`,
            iconSize: [16, 16],
            iconAnchor: [8, 8]
        });

        // ============================================================
        // 🔥 SAFE-BYPASS: INJEKSI MARKER MANUAL (GARANSI PASTI MUNCUL)
        // ============================================================
        // 1. Plotting Paksa Koordinat Rusia (Moskow)
        L.marker([55.7558, 37.6173], { icon: attackIcon }).addTo(map)
            .bindPopup(`<div class="p-1 text-slate-900 font-sans w-40">
                <p class="font-black text-rose-600 m-0 text-xs">🚨 SIMULATION: DDoS</p>
                <hr class="my-1 border-slate-300">
                <p class="m-0 text-[11px]"><b>Origin:</b> Russia</p>
                <p class="m-0 text-[11px]"><b>Severity:</b> CRITICAL</p>
            </div>`);

        // 2. Plotting Paksa Koordinat China (Beijing)
        L.marker([39.9042, 116.4074], { icon: attackIcon }).addTo(map)
            .bindPopup(`<div class="p-1 text-slate-900 font-sans w-40">
                <p class="font-black text-amber-600 m-0 text-xs">🚨 SIMULATION: Web Attack</p>
                <hr class="my-1 border-slate-300">
                <p class="m-0 text-[11px]"><b>Origin:</b> China</p>
                <p class="m-0 text-[11px]"><b>Severity:</b> HIGH</p>
            </div>`);

        // Loop data asli dari database MySQL jika terisi
        if (attackLocations && attackLocations.length > 0) {
            attackLocations.forEach(function(loc) {
                if (loc.latitude && loc.longitude) {
                    const marker = L.marker([parseFloat(loc.latitude), parseFloat(loc.longitude)], { icon: attackIcon }).addTo(map);
                    
                    marker.bindPopup(`
                        <div class="p-1 text-slate-900 font-sans w-40">
                            <p class="font-black text-rose-600 m-0 text-xs">🚨 ATTACK DETECTED</p>
                            <hr class="my-1 border-slate-300">
                            <p class="m-0 text-[11px]"><b>Type:</b> ${loc.prediction}</p>
                            <p class="m-0 text-[11px]"><b>Origin:</b> ${loc.country}</p>
                            <p class="m-0 text-[11px]"><b>Timestamp:</b> ${loc.detected_at}</p>
                        </div>
                    `);
                }
            });
        }

        // --- INISIALISASI MODEL COMPARISON GROUPED BAR CHART ---
        const modelCompData = @json($modelComparison);

        const barOptions = {
            chart: { 
                type: 'bar', 
                height: 350,
                backgroundColor: 'transparent',
                toolbar: { show: false }
            },
            plotOptions: {
                bar: {
                    horizontal: false,
                    columnWidth: '55%',
                    endingShape: 'rounded'
                },
            },
            dataLabels: {
                enabled: true,
                style: {
                    colors: ['#fff'],
                    fontSize: '10px'
                },
                formatter: function (val) {
                    return (val * 100).toFixed(1) + "%";
                }
            },
            stroke: {
                show: true,
                width: 2,
                colors: ['transparent']
            },
            series: modelCompData.models, 
            xaxis: {
                categories: modelCompData.metrics,
                labels: { style: { colors: '#94a3b8' } }
            },
            yaxis: {
                max: 1.0,
                labels: { 
                    style: { colors: '#94a3b8' },
                    formatter: function (val) {
                        return (val * 100) + "%";
                    }
                }
            },
            colors: ['#6366f1', '#0ea5e9', '#f97316'], 
            legend: { 
                position: 'top',
                labels: { colors: '#94a3b8' } 
            },
            grid: { 
                borderColor: '#334155',
                strokeDashArray: 4
            },
            tooltip: {
                theme: 'dark',
                y: {
                    formatter: function (val) {
                        return (val * 100).toFixed(2) + " %";
                    }
                }
            }
        };

        new ApexCharts(document.querySelector("#modelComparisonBarChart"), barOptions).render();
    </script>
</body>
</html>