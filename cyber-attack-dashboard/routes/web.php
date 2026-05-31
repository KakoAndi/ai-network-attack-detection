<?php

use App\Http\Controllers\NetworkTrafficController;
use Illuminate\Support\Facades\Route;


Route::get('/', [NetworkTrafficController::class, 'index'])->name('dashboard');
Route::post('/analyze', [NetworkTrafficController::class, 'analyze'])->name('traffic.analyze');
// Endpoint Webhook Receiver untuk menerima laporan otomatis dari Python FastAPI
// Ganti .php menjadi ::class
Route::post('/webhook/live-traffic', [NetworkTrafficController::class, 'handleLiveWebhook']);