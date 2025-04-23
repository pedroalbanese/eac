#!/usr/bin/php
<?php
include "AnubisEAC.php";

$key = hex2bin("00000000000000000000000000000000");  // Exemplo de chave
// $nonce = str_repeat("\0", 12);
$nonce = random_bytes(12);
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

// Parse Ciphertext

$full = $nonce . $ciphertext . $tag;
echo bin2hex($full) . "\n";

// Função extra: descriptografar uma mensagem no formato nonce|ciphertext|tag
function decryptEACParsed($anubis, $key, $header, $fullMessage) {
    $nonce = substr($fullMessage, 0, 12);
    $tag = substr($fullMessage, -16);
    $ciphertext = substr($fullMessage, 12, -16);
    return $anubis->decryptEAC($key, $nonce, $header, $ciphertext, $tag);
}

try {
    $decrypted = decryptEACParsed($anubis, $key, $header, $full);
    echo "Decifrado (parsed): $decrypted\n";
} catch (Exception $e) {
    echo "Erro (parsed): " . $e->getMessage() . "\n";
}
