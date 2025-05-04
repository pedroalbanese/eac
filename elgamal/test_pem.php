<?php

require_once 'elgamal.php';

function save_elgamal_private_pem($filename, $P, $G, $X, $asn1) {
    $der = $asn1->encode_private_key([
        'p' => $P,
        'g' => $G,
        'x' => $X
    ]);
    $base64 = chunk_split(base64_encode($der), 64, "\n");
    $pem = "-----BEGIN ELGAMAL PRIVATE KEY-----\n" . $base64 . "-----END ELGAMAL PRIVATE KEY-----\n";
    file_put_contents($filename, $pem);
}

function read_elgamal_private_pem($filename, $asn1) {
    $pem = file_get_contents($filename);
    $pem = preg_replace("/-----.*?-----/", "", $pem);
    $der = base64_decode($pem);
    return $asn1->decode_private_key($der);
}

function save_elgamal_public_pem($filename, $P, $G, $Y, $asn1) {
    $der = $asn1->encode_parameters([
        'p' => $P,
        'g' => $G,
        'y' => $Y
    ]);

    $base64 = chunk_split(base64_encode($der), 64, "\n");
    $pem = "-----BEGIN ELGAMAL PUBLIC KEY-----\n" . $base64 . "-----END ELGAMAL PUBLIC KEY-----\n";

    file_put_contents($filename, $pem);
}

function read_elgamal_public_pem($filename, $asn1) {
    $pem = file_get_contents($filename);
    $pem = preg_replace("/-----.*?-----/", "", $pem);
    $der = base64_decode($pem);
    return $asn1->decode_parameters($der);
}

function main() {
    $elgamal = new ElGamalCrypto();
    $asn1 = new ElGamalASN1();

    echo "🔧 Gerando chaves...\n";

    $x = $elgamal->hexToDec("2244f8d60ab7d1f907866c3388a522d2afed27c3a6fb3739c480d041d377174c");
    $y = $elgamal->modexp(ELGAMAL_G, $x, ELGAMAL_P);

    // Salvar chaves
    save_elgamal_public_pem("Public.pem", ELGAMAL_P, ELGAMAL_G, $y, $asn1);
    save_elgamal_private_pem("Private.pem", ELGAMAL_P, ELGAMAL_G, $x, $asn1);
    echo "✅ Chaves salvas em Public.pem e Private.pem\n";

    // Ler novamente
    $pub = read_elgamal_public_pem("Public.pem", $asn1);
    $priv = read_elgamal_private_pem("Private.pem", $asn1);

    $P = $pub['p'];
    $G = $pub['g'];
    $Y = $pub['y'];
    $X = $priv['x'];

    echo "🔑 Chaves carregadas com sucesso.\n";

    // Mensagem
    $message = "Mensagem secreta para teste de criptografia!";
    echo "📩 Mensagem original: $message\n";

    // Criptografar
    $cipher = $elgamal->elgamal_encrypt($message, $P, $G, $Y);
    $cipherDer = $asn1->encode_ciphertext($cipher);
    echo "🔐 Cifrado (DER hex):\n" . bin2hex($cipherDer) . "\n";

    // Descriptografar
    $decrypted = $elgamal->elgamal_decrypt($cipher['c1'], $cipher['c2'], $P, $X);
    echo "🔓 Mensagem descriptografada: $decrypted\n";

    if ($message === $decrypted) {
        echo "✅ Criptografia/Descriptografia bem-sucedida!\n";
    } else {
        echo "❌ Falha na descriptografia.\n";
    }
}

main();
