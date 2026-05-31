<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Exception;

class CyberAttackDetectionService
{
    private string $baseUrl;

    public function __construct()
    {
        $this->baseUrl = config('services.fastapi.url');
    }

    /**
     * Mengirim single flow traffic ke FastAPI untuk diprediksi
     */
    public function predictSingle(array $features): ?array
    {
        try {
            $response = Http::timeout(10)
                ->retry(2, 100)
                ->post("{$this->baseUrl}/predict", $features);

            if ($response->successful()) {
                return $response->json();
            }

            Log::error('FastAPI Engine Error: ' . $response->status());
            return null;
        } catch (Exception $e) {
            Log::error('Koneksi ke FastAPI Gagal: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Mengecek apakah service FastAPI online
     */
    public function healthCheck(): bool
    {
        try {
            $response = Http::timeout(3)->get("{$this->baseUrl}/");
            return $response->successful() && $response->json()['status'] === 'running';
        } catch (Exception $e) {
            return false;
        }
    }
}