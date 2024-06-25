<?php

namespace Nauhand\LaravelDataEncryption\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use OpenSSLAsymmetricKey;
use RuntimeException;

class DataEncryptionService
{
    private const CIPHER = 'AES-256-CBC';

    /**
     * Decrypt the given encrypted value.
     *
     * @param  string  $value  The base64 encoded value to decrypt.
     * @return mixed The decrypted data.
     *
     * @throws RuntimeException If there is an error during decryption.
     */
    public function decrypt(string $value, string $privatePath): mixed
    {
        try {
            $privateKeyResource = $this->getPrivateKeyResource($privatePath);
            $keyParts = explode(':', base64_decode($value));

            if (is_array($keyParts) && count($keyParts) > 1) {
                [$encryptedAesKey, $encryptedData] = $keyParts;

                $aesKey = $this->decryptAesKey($encryptedAesKey, $privateKeyResource);
                $decryptedData = $this->decryptData($encryptedData, $aesKey);

                return json_decode($decryptedData, true);
            }

            return $value;
        } catch (RuntimeException $e) {
            Log::error($e->getMessage());
            throw new RuntimeException('Une erreur est survenue: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Encrypt the specified attribute from the request using public key encryption.
     *
     * @param  Request|null  $request  The HTTP request containing the data to encrypt.
     * @param  mixed  $attribute  The attribute in the request to encrypt.
     * @return string The encrypted data.
     *
     * @throws RuntimeException If there is an error during encryption.
     */
    public function encrypt(mixed $attribute, string $publicPath, ?Request $request = null): string
    {
        try {
            $dataToEncrypt = is_null($request) ? $attribute : $request->input($attribute);
            $publicKeyResource = $this->getPublicKeyResource($publicPath);
            $aesKey = openssl_random_pseudo_bytes(32);
            $dataToEncryptEncoded = json_encode($dataToEncrypt, JSON_THROW_ON_ERROR);
            $encryptedData = $this->encryptData($dataToEncryptEncoded, $aesKey);
            $encryptedAesKey = $this->encryptAesKey($aesKey, $publicKeyResource);

            $combinedData = base64_encode($encryptedAesKey).':'.base64_encode($encryptedData);

            return base64_encode($combinedData);
        } catch (RuntimeException $e) {
            Log::error($e->getMessage());
            throw new RuntimeException('Une erreur est survenue: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Get the public key resource from the public key file.
     *
     * @return OpenSSLAsymmetricKey The OpenSSL public key resource.
     *
     * @throws RuntimeException If the public key file cannot be read or the key is invalid.
     */
    private function getPublicKeyResource(string $publicPath): OpenSSLAsymmetricKey
    {
        $publicKey = file_get_contents(storage_path($publicPath));
        if (is_null($publicKey)) {
            throw new RuntimeException('Unable to read public key file.');
        }

        $publicKeyResource = openssl_pkey_get_public($publicKey);
        if (! $publicKeyResource) {
            throw new RuntimeException('Invalid public key.');
        }

        return $publicKeyResource;
    }

    /**
     * Encrypt the data using the AES key.
     *
     * @param  string  $data  The data to encrypt.
     * @param  string  $aesKey  The AES key.
     * @return string The encrypted data.
     *
     * @throws RuntimeException If the data cannot be encrypted.
     */
    private function encryptData(string $data, string $aesKey): string
    {
        $encryptedData = openssl_encrypt($data, self::CIPHER, $aesKey, 0, substr($aesKey, 0, 16));

        if (! $encryptedData) {
            throw new RuntimeException('Unable to encrypt data.');
        }

        return $encryptedData;
    }

    /**
     * Encrypt the AES key using the public key.
     *
     * @param  string  $aesKey  The AES key to encrypt.
     * @param  OpenSSLAsymmetricKey  $publicKeyResource  The public key resource.
     * @return string The encrypted AES key.
     *
     * @throws RuntimeException If the AES key cannot be encrypted.
     */
    private function encryptAesKey(string $aesKey, OpenSSLAsymmetricKey $publicKeyResource): string
    {
        if (! openssl_public_encrypt($aesKey, $encryptedAesKey, $publicKeyResource) && $msg = openssl_error_string()) {
            Log::error($msg);
            throw new RuntimeException('Une erreur est survenue lors du cryptage des données '.$msg);
        }

        return $encryptedAesKey;
    }

    /**
     * Get the private key resource from the private key file.
     *
     * @return OpenSSLAsymmetricKey The OpenSSL private key resource.
     *
     * @throws RuntimeException If the private key file cannot be read or the key is invalid.
     */
    private function getPrivateKeyResource(string $privatePath): OpenSSLAsymmetricKey
    {
        $privateKey = file_get_contents(storage_path($privatePath));
        if (is_null($privateKey)) {
            throw new RuntimeException('Unable to read private key file.');
        }

        $privateKeyResource = openssl_pkey_get_private($privateKey);
        if ($privateKeyResource === false) {
            throw new RuntimeException('Invalid private key.');
        }

        return $privateKeyResource;
    }

    /**
     * Decrypt the AES key using the private key resource.
     *
     * @param  string  $encryptedAesKey  The base64 encoded encrypted AES key.
     * @param  OpenSSLAsymmetricKey  $privateKeyResource  The OpenSSL private key resource.
     * @return string The decrypted AES key.
     *
     * @throws RuntimeException If the AES key cannot be decrypted.
     */
    private function decryptAesKey(string $encryptedAesKey, OpenSSLAsymmetricKey $privateKeyResource): string
    {
        if (! openssl_private_decrypt(base64_decode($encryptedAesKey), $aesKey, $privateKeyResource)) {
            throw new RuntimeException('Unable to decrypt AES key.');
        }

        return $aesKey;
    }

    /**
     * Decrypt the data using the AES key.
     *
     * @param  string  $encryptedData  The base64 encoded encrypted data.
     * @param  string  $aesKey  The AES key.
     * @return string The decrypted data as a string.
     *
     * @throws RuntimeException If the data cannot be decrypted.
     */
    private function decryptData(string $encryptedData, string $aesKey): string
    {
        $decryptedData = openssl_decrypt(base64_decode($encryptedData), self::CIPHER, $aesKey, 0, substr($aesKey, 0, 16));

        if ($decryptedData === false) {
            throw new RuntimeException('Unable to decrypt data.');
        }

        return $decryptedData;
    }
}
