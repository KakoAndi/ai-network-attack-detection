<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class NetworkTraffic extends Model
{
    // Tambahkan baris ini untuk mengunci nama tabel yang benar
    protected $table = 'network_traffics';

    protected $fillable = [
        'destination_port', 
        'flow_duration', 
        'prediction', 
        'confidence', 
        'severity_level', 
        'is_attack', 
        'raw_features', 
        'detected_at'
    ];
}