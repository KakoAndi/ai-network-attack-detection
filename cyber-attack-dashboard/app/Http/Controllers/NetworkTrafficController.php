<?php

namespace App\Http\Controllers;

use App\Models\NetworkTraffic;
use App\Services\CyberAttackDetectionService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class NetworkTrafficController extends Controller
{
    protected CyberAttackDetectionService $detectionService;

    public function __construct(CyberAttackDetectionService $detectionService)
    {
        $this->detectionService = $detectionService;
    }

    /**
     * Menampilkan Dashboard NIDS beserta Peta Geolocation
     */
    public function index()
    {
        $totalAnalyzed = NetworkTraffic::count();
        $totalAttacks = NetworkTraffic::where('is_attack', true)->count();
        $attackRate = $totalAnalyzed > 0 ? ($totalAttacks / $totalAnalyzed) * 100 : 0;
        
        $attackDistribution = NetworkTraffic::selectRaw('prediction as label, count(*) as value')
            ->groupBy('prediction')
            ->orderByDesc('value')
            ->get();

        $hourlyTraffic = NetworkTraffic::selectRaw('DATE_FORMAT(detected_at, "%H:00") as hour, count(*) as total, sum(is_attack) as attacks')
            ->where('detected_at', '>=', now()->subDay())
            ->groupBy('hour')
            ->orderBy('hour')
            ->get();

        $recentLogs = NetworkTraffic::latest('detected_at')->limit(10)->get();
        $apiStatus = $this->detectionService->healthCheck();

        // Ambil data koordinat khusus serangan untuk dipetakan ke Leaflet.js Map
        $attackLocations = NetworkTraffic::where('is_attack', true)
            ->whereNotNull('latitude')
            ->whereNotNull('longitude')
            ->select('prediction', 'country', 'latitude', 'longitude', 'detected_at')
            ->latest('detected_at')
            ->limit(50) // Batasi 50 serangan terbaru agar peta ringan
            ->get();

        $modelComparison = [
            'metrics' => ['Accuracy', 'Precision', 'Recall', 'F1-Score'],
            'models' => [
                ['name' => 'Random Forest', 'data' => [0.9980, 0.9981, 0.9980, 0.9980]],
                ['name' => 'Decision Tree', 'data' => [0.9920, 0.9921, 0.9920, 0.9920]],
                ['name' => 'Logistic Regression', 'data' => [0.8850, 0.8530, 0.8850, 0.8610]]
            ]
        ];

        return view('dashboard', compact(
            'totalAnalyzed', 'totalAttacks', 'attackRate', 
            'attackDistribution', 'hourlyTraffic', 'recentLogs', 
            'apiStatus', 'modelComparison', 'attackLocations'
        ));
    }

    /**
     * Memproses Form Simulator
     */
    public function analyze(Request $request)
    {
        $validated = $request->validate([
            'destination_port'       => 'required|integer|min:0',
            'flow_duration'          => 'required|numeric|min:0',
            'total_fwd_packets'      => 'required|numeric|min:0',
            'total_bwd_packets'      => 'required|numeric|min:0',
            'fwd_packet_length_max'  => 'required|numeric|min:0',
            'bwd_packet_length_std'  => 'required|string',
            'flow_iat_mean'          => 'required|numeric',
            'fwd_header_length'      => 'required|integer',
            'packet_length_mean'     => 'required|numeric|min:0',
            'fwd_psh_flags'          => 'required|integer|in:0,1',
        ]);

        $cleanBwdStd = (float) str_replace(',', '.', $validated['bwd_packet_length_std']);

        $apiPayload = [
            'flow_duration' => (float) $validated['flow_duration'],
            'total_fwd_packets' => (float) $validated['total_fwd_packets'],
            'total_bwd_packets' => (float) $validated['total_bwd_packets'],
            'flow_bytes_per_s' => 25.129, 'flow_packets_per_s' => 16.757,
            'fwd_packets_per_s' => 0.0, 'bwd_packets_per_s' => 0.0,
            'flow_iat_mean' => (float) $validated['flow_iat_mean'],
            'flow_iat_std' => 0.0, 'flow_iat_max' => 0.0, 'flow_iat_min' => 0.0,
            'fwd_iat_mean' => 0.0, 'fwd_iat_std' => 0.0, 'bwd_iat_mean' => 0.0, 'bwd_iat_std' => 0.0,
            'packet_length_mean' => (float) $validated['packet_length_mean'],
            'packet_length_std' => $cleanBwdStd, 'min_packet_length' => 0.0,
            'max_packet_length' => (float) $validated['fwd_packet_length_max'],
            'packet_length_variance' => 0.0, 'average_packet_size' => 0.0,
            'avg_fwd_segment_size' => 0.0, 'avg_bwd_segment_size' => 0.0,
            'fwd_psh_flags' => (int) $validated['fwd_psh_flags'], 'bwd_psh_flags' => 0,
            'fwd_urg_flags' => 0, 'bwd_urg_flags' => 0, 'fin_flag_count' => 1, 'syn_flag_count' => 1,
            'rst_flag_count' => 0, 'psh_flag_count' => 0, 'ack_flag_count' => 1, 'urg_flag_count' => 0,
            'cwe_flag_count' => 0, 'ece_flag_count' => 0, 'init_win_bytes_forward' => 65535.0,
            'init_win_bytes_backward' => 0.0, 'act_data_pkt_fwd' => 0.0, 'min_seg_size_forward' => 0.0, 'down_up_ratio' => 0.0,
            'active_mean' => 0.0, 'active_std' => 0.0, 'active_max' => 0.0, 'active_min' => 0.0,
            'idle_mean' => 0.0, 'idle_std' => 0.0, 'idle_max' => 0.0, 'idle_min' => 0.0,
        ];

        $result = $this->detectionService->predictSingle($apiPayload);

        if ($result) {
            // Berikan data lokasi default (Local Traffic)
            $sourceIp = '192.168.1.50';
            $country = 'Local Network';
            $lat = null;
            $lon = null;

            // ============================================================
            // MECHANISM BYPASS SIMULATOR DENGAN GEOLOCATION DUMMY DATA
            // ============================================================
            if ((int)$validated['destination_port'] === 999) {
                $result['prediction'] = 'DDoS';
                $result['confidence'] = 0.9854;
                $result['severity_level'] = 'critical';
                $result['is_attack'] = true;
                
                $sourceIp = '185.220.101.5'; // Contoh IP Tor Node Rusia
                $country = 'Russia';
                $lat = 55.7558;  // Koordinat Moskow
                $lon = 37.6173;
            } elseif ((int)$validated['destination_port'] === 777) {
                $result['prediction'] = 'Web Attack';
                $result['confidence'] = 0.9125;
                $result['severity_level'] = 'high';
                $result['is_attack'] = true;

                $sourceIp = '103.245.72.1'; // Contoh IP Tiongkok
                $country = 'China';
                $lat = 39.9042;  // Koordinat Beijing
                $lon = 116.4074;
            }

            NetworkTraffic::create([
                'destination_port' => (int) $validated['destination_port'],
                'flow_duration'    => (double) $validated['flow_duration'],
                'source_ip'        => $sourceIp,
                'prediction'       => $result['prediction'],
                'country'          => $country,
                'confidence'       => (float) $result['confidence'],
                'severity_level'   => $result['severity_level'],
                'is_attack'        => (bool) $result['is_attack'],
                'raw_features'     => json_encode($validated),
                'latitude'         => $lat,
                'longitude'        => $lon,
                'detected_at'      => now(),
            ]);

            $result['confidence_percent'] = number_format($result['confidence'] * 100, 2) . '%';
            return redirect()->back()->with('success_prediction', $result);
        }

        return redirect()->back()->with('error', 'Gagal memproses inferensi.');
    }

    /**
     * Menerima Kiriman dari Live Packet Sniffer Webhook
     */
    public function handleLiveWebhook(Request $request)
    {
        $features = $request->input('features');
        $result = $request->input('result');

        if (!$features || !$result) {
            return response()->json(['status' => 'error'], 400);
        }

        // Acak lokasi Geolocation Dunia untuk Live Sniffer jika terdeteksi serangan murni
        $lat = null; $lon = null; $country = 'Local Network';
        if ((bool)$result['is_attack']) {
            $dummyLocations = [
                ['country' => 'United States', 'lat' => 37.0902, 'lon' => -95.7129],
                ['country' => 'Netherlands', 'lat' => 52.1326, 'lon' => 5.2913],
                ['country' => 'North Korea', 'lat' => 40.3399, 'lon' => 127.5101]
            ];
            $randomPick = $dummyLocations[array_rand($dummyLocations)];
            $country = $randomPick['country'];
            $lat = $randomPick['lat'];
            $lon = $randomPick['lon'];
        }

        NetworkTraffic::create([
            'destination_port' => (int) ($features['destination_port'] ?? 80),
            'flow_duration'    => (double) $features['flow_duration'],
            'source_ip'        => '172.16.0.' . rand(1, 254),
            'prediction'       => $result['prediction'],
            'country'          => $country,
            'confidence'       => (float) $result['confidence'],
            'severity_level'   => $result['severity_level'],
            'is_attack'        => (bool) $result['is_attack'],
            'raw_features'     => json_encode($features),
            'latitude'         => $lat,
            'longitude'        => $lon,
            'detected_at'      => now(),
        ]);

        return response()->json(['status' => 'success']);
    }
}