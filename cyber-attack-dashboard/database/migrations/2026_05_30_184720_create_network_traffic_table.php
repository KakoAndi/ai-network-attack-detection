<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
{
    Schema::create('network_traffics', function (Blueprint $table) {
        $table->id();
        $table->unsignedInteger('destination_port');
        $table->double('flow_duration');
        $table->string('prediction'); // BENIGN, DDoS, Bot, dll
        $table->decimal('confidence', 5, 4); // Score dari model (cth: 0.9850)
        $table->string('severity_level'); // none, low, medium, high, critical
        $table->boolean('is_attack');
        $table->text('raw_features'); // Menyimpan payload input JSON
        $table->timestamp('detected_at');
        $table->timestamps();
    });
}

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('network_traffic');
    }

    
};
