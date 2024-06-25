<?php

namespace Nauhand\LaravelDataEncryption;

use Illuminate\Support\ServiceProvider;

class DataEncryptionServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('DataEncryptionService', function ($app) {
            return new Services\DataEncryptionService();
        });
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }
}
