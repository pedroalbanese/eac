<?php
require_once 'elgamal.php';

// Configuração de chaves
$x = ElGamalCrypto::hexToDec("2244f8d60ab7d1f907866c3388a522d2afed27c3a6fb3739c480d041d377174c");
$y = ElGamalCrypto::modexp(ELGAMAL_G, $x, ELGAMAL_P);

// Mensagem de teste
$message = "Mensagem secreta para teste de criptografia e assinatura!";

echo "=== Teste de Criptografia ElGamal ===\n";

// 1. Criptografar
$cipher = ElGamalCrypto::elgamal_encrypt($message, ELGAMAL_P, ELGAMAL_G, $y);
ElGamalFile::save_ciphertext('cipher.txt', $cipher);

echo "Mensagem original: $message\n";
echo "Texto cifrado:\n";
echo "c1 = " . ElGamalCrypto::bcdechex($cipher['c1']) . "\n";
echo "c2 = " . ElGamalCrypto::bcdechex($cipher['c2']) . "\n";

// 2. Descriptografar
$cipher = ElGamalFile::read_ciphertext('cipher.txt');
$decrypted = ElGamalCrypto::elgamal_decrypt($cipher['c1'], $cipher['c2'], ELGAMAL_P, $x);

echo "\nMensagem descriptografada: $decrypted\n";

// Verificação de criptografia
if ($message === $decrypted) {
    echo "✅ Criptografia/Descriptografia bem-sucedida!\n\n";
} else {
    echo "❌ Erro na criptografia/descriptografia!\n\n";
}

echo "=== Teste de Assinatura Digital ElGamal ===\n";

// 1. Gerar assinatura
$signature = ElGamalCrypto::elgamal_sign($message, ELGAMAL_P, ELGAMAL_G, $x);
ElGamalFile::save_signature('signature.txt', $signature);

echo "Assinatura gerada:\n";
echo "r = " . ElGamalCrypto::bcdechex($signature['r']) . "\n";
echo "s = " . ElGamalCrypto::bcdechex($signature['s']) . "\n";

// 2. Verificar assinatura
$signature = ElGamalFile::read_signature('signature.txt');
$valid = ElGamalCrypto::elgamal_verify($message, $signature['r'], $signature['s'], ELGAMAL_P, ELGAMAL_G, $y);

if ($valid) {
    echo "✅ Assinatura válida!\n";
} else {
    echo "❌ Assinatura inválida!\n";
}

echo "\n=== Teste Completo Concluído ===\n";
?>
