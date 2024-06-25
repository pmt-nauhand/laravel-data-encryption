<?php

namespace Nauhand\LaravelDataEncryption\Facades;

use Illuminate\Support\Facades\Facade;

class DataEncryption extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'DataEncryptionService';
    }
}