<?php
require_once 'elgamal.php';

$elgamal = new ElGamalCrypto();
$elgamalFile = new ElGamalFile();

// Configuração de chaves
$x = $elgamal->hexToDec("2244f8d60ab7d1f907866c3388a522d2afed27c3a6fb3739c480d041d377174c");
$y = $elgamal->modexp(ELGAMAL_G, $x, ELGAMAL_P);

// Mensagem de teste
$message = "Mensagem secreta para teste de criptografia e assinatura!";

echo "=== Teste de Criptografia ElGamal ===\n";

// 1. Criptografar
$cipher = $elgamal->elgamal_encrypt($message, ELGAMAL_P, ELGAMAL_G, $y);
$elgamalFile->save_ciphertext('cipher.txt', $cipher);

echo "Mensagem original: $message\n";
echo "Texto cifrado:\n";
echo "c1 = " . $elgamal->bcdechex($cipher['c1']) . "\n";
echo "c2 = " . $elgamal->bcdechex($cipher['c2']) . "\n";

// 2. Descriptografar
$cipher = $elgamalFile->read_ciphertext('cipher.txt');
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
$elgamalFile->save_signature('signature.txt', $signature);

echo "Assinatura gerada:\n";
echo "r = " . $elgamal->bcdechex($signature['r']) . "\n";
echo "s = " . $elgamal->bcdechex($signature['s']) . "\n";

// 2. Verificar assinatura
$signature = $elgamalFile->read_signature('signature.txt');
$valid = $elgamal->elgamal_verify($message, $signature['r'], $signature['s'], ELGAMAL_P, ELGAMAL_G, $y);

if ($valid) {
    echo "✅ Assinatura válida!\n";
} else {
    echo "❌ Assinatura inválida!\n";
}

echo "\n=== Teste Completo Concluído ===\n";
?>
