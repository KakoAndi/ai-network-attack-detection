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
    Schema::table('network_traffics', function (Blueprint $table) {
        $table->string('source_ip')->nullable()->after('destination_port');
        $table->string('country')->nullable()->after('prediction');
        $table->decimal('latitude', 10, 8)->nullable()->after('raw_features');
        $table->decimal('longitude', 11, 8)->nullable()->after('latitude');
    });
}

public function down(): void
{
    Schema::table('network_traffics', function (Blueprint $table) {
        $table->dropColumn(['source_ip', 'country', 'latitude', 'longitude']);
    });
}
};
