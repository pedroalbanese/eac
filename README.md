# EAC (DLIES) 🇧🇷 
EAC Authenticated Mode of Operation

#### EAC: Um Esquema Híbrido de DLIES com Ciphersuites Brasileiras

O EAC (Encrypt-then-Authenticate-then-Combine) é um esquema de criptografia híbrida que combina ElGamal Key Agreement, assinatura digital e primitivas criptográficas brasileiras, incluindo a cifra de bloco Anubis, o modo de operação EAC, e função de hash Whirlpool, além de esquemas de autenticação e derivação de chave como HMAC, HKDF e PBKDF2.

Ele é interoperável entre PHP e Go, mas pode ser usado de forma independente em qualquer sistema. Projetado para segurança e eficiência, o EAC é uma escolha robusta para aplicações que exigem confidencialidade, autenticidade e integridade.

### EAC Exemplo de Uso
```php
<?php
include "EAC.php";

$key = hex2bin("00000000000000000000000000000000");  // Exemplo de chave
$nonce = str_repeat("\0", 12);
$header = "cabecalho";
$plaintext = "mensagem secreta com eac";

$anubis = new Anubis();
list($ciphertext, $tag) = $anubis->encryptEAC($key, $nonce, $header, $plaintext);

echo "Cifrado: " . bin2hex($ciphertext) . "\n";
echo "Tag:     " . bin2hex($tag) . "\n";

echo bin2hex($nonce . $ciphertext . $tag) . "\n";

try {
    $decrypted = $anubis->decryptEAC($key, $nonce, $header, $ciphertext, $tag);
    echo "Decifrado: $decrypted\n";
} catch (Exception $e) {
    echo "Erro: " . $e->getMessage() . "\n";
}
```
### ElGamal Exemplo de Uso
```php
<?php
require_once 'elgamal.php';

$elgamal = new ElGamalCrypto();

// Configuração de chaves
$x = $elgamal->hexToDec("2244f8d60ab7d1f907866c3388a522d2afed27c3a6fb3739c480d041d377174c");
$y = $elgamal->modexp(ELGAMAL_G, $x, ELGAMAL_P);

// Mensagem de teste
$message = "Mensagem secreta para teste de criptografia e assinatura!";

echo "=== Teste de Criptografia ElGamal ===\n";

// 1. Criptografar
$cipher = $elgamal->elgamal_encrypt($message, ELGAMAL_P, ELGAMAL_G, $y);

echo "Mensagem original: $message\n";
echo "Texto cifrado:\n";
echo "c1 = " . $elgamal->bcdechex($cipher['c1']) . "\n";
echo "c2 = " . $elgamal->bcdechex($cipher['c2']) . "\n";

// 2. Descriptografar
$decrypted = $elgamal->elgamal_decrypt($cipher['c1'], $cipher['c2'], ELGAMAL_P, $x);

echo "\nMensagem descriptografada: $decrypted\n";

// Verificação de criptografia
if ($message === $decrypted) {
    echo "✅ Criptografia/Descriptografia bem-sucedida!\n\n";
} else {
    echo "❌ Erro na criptografia/descriptografia!\n\n";
}

echo "=== Teste de Assinatura Digital ElGamal ===\n";

// 1. Gerar assinatura
$signature = $elgamal->elgamal_sign($message, ELGAMAL_P, ELGAMAL_G, $x);

echo "Assinatura gerada:\n";
echo "r = " . $elgamal->bcdechex($signature['r']) . "\n";
echo "s = " . $elgamal->bcdechex($signature['s']) . "\n";

// 2. Verificar assinatura
$valid = $elgamal->elgamal_verify($message, $signature['r'], $signature['s'], ELGAMAL_P, ELGAMAL_G, $y);

if ($valid) {
    echo "✅ Assinatura válida!\n";
} else {
    echo "❌ Assinatura inválida!\n";
}

echo "\n=== Teste Completo Concluído ===\n";
?>
```

### Primitivas Criptográficas Anubis
```php
<?php
include "EAC.php";
$plainText = "Mensagem confidencial que precisa ser criptografada";
$key = hex2bin("00000000000000000000000000000000");  // Exemplo de chave
$iv = str_repeat("\0", 16);  // Exemplo de IV (contador) com 16 bytes zero

$crypt = new Anubis();
$encryptedData = $crypt->ctrMode($plainText, $key, $iv);

echo bin2hex($encryptedData) ."\n";

// Para descriptografar, basta chamar o mesmo método com os dados cifrados:
$decryptedData = $crypt->ctrMode($encryptedData, $key, $iv);

echo $decryptedData ."\n";  // Deve imprimir a mensagem original

$key = "0000000000000000";  // Exemplo de chave
$cmac = new Anubis($key);
$msg = "mensagem de teste";

$mac = $cmac->generate($msg);
echo "CMAC: " . bin2hex($mac) . PHP_EOL;
```

### Primitivas Criptográficas Whirlpool
```php
<?php
$plainText = "Mensagem confidencial que precisa ser criptografada";

function hmac($key, $message) {
    $blockSize = 64;

    if (strlen($key) > $blockSize) {
        $key = hash("whirlpool", $key, true);
    }
    if (strlen($key) < $blockSize) {
        $key = str_pad($key, $blockSize, "\0");
    }

    $o_key_pad = $i_key_pad = '';
    for ($i = 0; $i < $blockSize; $i++) {
        $k = ord($key[$i]);
        $o_key_pad .= chr($k ^ 0x5c);
        $i_key_pad .= chr($k ^ 0x36);
    }

    $innerHash = hash("whirlpool", $i_key_pad . $message, true);
    return hash("whirlpool", $o_key_pad . $innerHash, true);  
}

function hkdf($ikm, $length, $salt = "", $info = "") {
    $hashLen = 64;

    // Etapa 1: Extract
    if ($salt === "") {
        $salt = str_repeat("\0", $hashLen);
    }
    $prk = hmac($salt, $ikm);

    // Etapa 2: Expand
    $okm = "";
    $t = "";
    $counter = 1;
    while (strlen($okm) < $length) {
        $t = hmac($prk, $t . $info . chr($counter));
        $okm .= $t;
        $counter++;
    }

    return substr($okm, 0, $length);
}

function pbkdf2($password, $salt, $iterations, $dkLen) {
    $hashLen = 64; // Whirlpool = 512 bits = 64 bytes
    $blockCount = ceil($dkLen / $hashLen);
    $output = '';

    for ($i = 1; $i <= $blockCount; $i++) {
        // INT_32_BE(i)
        $intBlock = pack("N", $i);

        $u = hmac($password, $salt . $intBlock);
        $t = $u;

        for ($j = 1; $j < $iterations; $j++) {
            $u = hmac($password, $u);
            $t ^= $u;  // XOR acumulado
        }

        $output .= $t;
    }

    return substr($output, 0, $dkLen); 
}

// --- Exemplo de uso ---
$key = "chave-secreta";
$hash = hash("whirlpool", $plainText);

$hmac = hmac($key, $plainText);

echo "Mensagem: " . $plainText . PHP_EOL;
echo "Hash (hex): " . $hash . PHP_EOL;
echo "HMAC (hex): " . bin2hex($hmac) . PHP_EOL;

$keyMaterial = "material-chave-bruto";
$salt = "sal-de-exemplo";
$info = "contexto";
$outputLength = 64; // 64 bytes

$okm = hkdf($keyMaterial, $outputLength, $salt, $info);
echo "HKDF OKM (hex): " . bin2hex($okm) . PHP_EOL;

$password = "senha-super-secreta";
$salt = "sal-unico";
$iterations = 1000;
$derivedKeyLen = 40;

$derivedKey = pbkdf2($password, $salt, $iterations, $derivedKeyLen);
echo "PBKDF2 com Whirlpool (hex): " . bin2hex($derivedKey) . PHP_EOL;
```

## Contribua
**Use _issues_ para tudo**
- Você pode ajudar e receber ajuda por meio de:
  - Relato de dúvidas e perguntas
- Você pode contribuir por meio de:
  - Relato de problemas (_issues_)
  - Sugestão de novos recursos ou melhorias
  - Aprimoramento ou correção da documentação

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2025 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
