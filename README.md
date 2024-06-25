# Laravel Data Encryption

A Laravel package for data encryption and decryption using RSA keys.

## Crédits

- **NAUHAND ALLOU** - Développeur principal - [Email](mailto:olivier.nauhand@gmail.com)

## Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## Installation

You can install the package via Composer:

```bash
composer require nauhand/laravel-data-encryption
```
## How to use

1. Generate RSA keys
First you'll need to generate a public and private RSA key. To do this, follow the instructions below

```bash
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
```
You can then store your private and public keys in the storage directory of your laravel application in any subfolder or directly in the root of the folder.

2. Laravel project configuration
Once your keys have been generated and stored, you will now add these two variables to the environment file : SSL_PUBLIC_KEY_PATH="your/storage/path/file.key" and SSL_PRIVATE_KEY_PATH="your/storage/path/file.key". Once this has been done, add these configurations to your config/app.php file so that the package can take them into account.

```bash
'ssl_public_key_path' => env('SSL_PUBLIC_KEY_PATH'),
'ssl_private_key_path' => env('SSL_PRIVATE_KEY_PATH'),
```

3. Encrypt and decrypt data
Now you can use the package to encrypt and decrypt data. Here's an example of how to do:

### To encrypt without $request: 

```bash
DataEncryption::encrypt($jsonString, config('app.ssl_public_key_path'));
```

### To encrypt with $request: 

```bash
DataEncryption::encrypt($jsonString, config('app.ssl_public_key_path'), $request);
```

### To decrypt : 

```bash
DataEncryption::decrypt($encryptedString, config('app.ssl_private_key_path'));
```
