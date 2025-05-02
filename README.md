# EAC (DLIES) 🇧🇷 
EAC Authenticated Mode of Operation

#### Camelo: Um Esquema DLIES Híbrido com Ciphersuites Brasileiras

O Camelo é um esquema de criptografia híbrido assíncrono para estabelecer um canal seguro entre duas partes através de um canal não-seguro (vide E2E), que combina ElGamal Key Agreement (Acordo de Chave Compartilhada), assinatura digital e primitivas criptográficas brasileiras, incluindo a cifra de bloco Anubis e a função de hash Whirlpool, ambas de coautoria de Paulo S. L. M. Barreto da Escola Politécnica da Universidade de São Paulo (USP), além de esquemas de autenticação e derivação de chave como HMAC, HKDF e PBKDF2, escrito em Puro Go e Puro PHP (sem necessidade de bibliotecas externas). Este exemplo usa parâmetros de 3072-bit que oferecem 128-bit de nível de segurança, mas parametros maiores podem ser gerados com a ferramenta `paramgen` deste mesmo projeto. O modo de operação EAC (Encrypt-then-Authenticate-then-Combine) é um modo AEAD (Authenticated Encryption with Associated Data).

#### Implementa
- Anubis Involutional SPN 128-bit block cipher (ESAT/COSIC)
- RFC 2104: HMAC - Keyed-Hashing for Message Authentication
- RFC 4493: Cipher-based Message Authentication Code (CMAC)
- RFC 4880, section 9.1. Public-Key Algorithms: Elgamal
- RFC 5869: HMAC-based Key Derivation Function (HKDF)
- RFC 6070: Password-Based Key Derivation Function 2 (PBKDF2)
- ISO/IEC 10118-3:2003 Whirlpool (ESAT/COSIC)

<details>
  <summary>Teoria do ElGamal</summary>  

#### Geração de Chaves

1. Gerar um número primo grande $p$.
2. Selecionar um gerador $g \in [2, p-2]$.
3. Gerar uma chave privada $x$ aleatoriamente.
4. Calcular a chave pública $Y = g^x \mod p$.

#### Assinatura Digital

1. Selecionar um valor aleatório $k$ tal que $1 < k < p-1$, $\text{gcd}(k, p-1) = 1$.
2. Calcular o primeiro componente da assinatura: $r = g^k \mod p$.
3. Calcular o segundo componente da assinatura: $s \equiv (H(m) - x \cdot r) \cdot k^{-1} \mod (p-1)$.

#### Verificação da Assinatura Digital

1. Receber a mensagem $m$ e os componentes da assinatura $(r, s)$.
2. Calcular $w \equiv s^{-1} \mod (p-1)$.
3. Calcular $u_1 \equiv H(m) \cdot w \mod (p-1)$.
4. Calcular $u_2 \equiv r \cdot w \mod (p-1)$.
5. Calcular $v \equiv g^{u_1} \cdot Y^{u_2} \mod p$.
6. A assinatura é válida se $v \equiv r \mod p$.

#### Acordo de Chaves

1. Bob gera seu par de chaves $(x_B, Y_B)$.
2. Bob compartilha sua chave pública $Y_B$ com Alice.
3. Alice gera uma chave simétrica aleatória $K_{\text{sym}}$.
4. Alice criptografa $K_{\text{sym}}$ usando a chave pública de Bob:  
   $a = g^{k_A} \mod p, \\
   b = Y_B^{k_A} \cdot K_{\text{sym}} \mod p$.
5. Alice envia o texto cifrado $(a, b)$ para Bob.
6. Bob decifra o texto recebido usando sua chave privada para obter:  
   $K_{\text{sym}} = (b \cdot a^{-x_B}) \mod p$.
7. Agora, tanto Alice quanto Bob possuem a chave simétrica compartilhada $K_{\text{sym}}$ para comunicação futura.

Onde:  
$H(m)$  Representa o valor de hash da mensagem (Whirlpool neste caso).  
$k^{-1}$  Denota o inverso multiplicativo modular de $k$ módulo $(p - 1)$.  
$\text{gcd}(a, b)$  Denota o Máximo Divisor Comum (MDC) de $a$ e $b$.  
$k_A$  É uma chave secreta aleatória conhecida apenas por Alice durante essa sessão.  
$\equiv$  Indica congruência.  

</details>

#### Protocolo Completo
```
Emissor                                                       Destinatário
  |                                                                 |
  |---(1) Gera chave simétrica------------------------------------->|
  |---(2) Criptografa mensagem com Anubis em modo AEAD------------->|
  |---(3) Encapsula chave simétrica com chave pública do receptor-->|
  |---(4) Assina criptograma--------------------------------------->|
  |---(5) Envia criptograma e assinatura--------------------------->|
  |                                                                 |
  |<--(6) Verifica assinatura com a chave pública do emissor--------|
  |<--(7) Desencapsula chave simétrica------------------------------|
  |<--(8) Descriptografa mensagem-----------------------------------|
```

Ele é interoperável entre PHP e Go, mas pode ser usado de forma independente em qualquer sistema. Projetado para segurança e eficiência, o EAC é uma escolha robusta para aplicações que exigem confidencialidade, autenticidade e integridade.

### EAC Exemplo de Uso (PHP)
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

### EAC Exemplo de Uso (Go)
```go
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	
	"github.com/pedroalbanese/eac"
)

func main() {
	// Chave hard-coded (128-bit Anubis)
	key, err := hex.DecodeString("00000000000000000000000000000000")
	if err != nil {
		log.Fatalf("hex decode key: %v", err)
	}
	
	// Dados hard-coded
	head := []byte("cabecalho")
	plaintext := []byte("mensagem secreta com eac")

	// Instancia AEAD
	aead, err := eac.NewEAC(key)

	if err != nil {
		log.Fatalf("new AEAD: %v", err)
	}

	// 1) Encrypt: Seal(dst, nonce, plaintext, associatedData)
	nonce := make([]byte, 12)
	
	// Prefix bit zero como no EAX
	nonce[0] &= 0x7F

	out := aead.Seal(nonce, nonce, plaintext, head)

	// Print hex: nonce | ciphertext | tag
	fmt.Println(hex.EncodeToString(out))

	// 2) Decrypt: separa nonce e ciphertext+tag
	nonce2 := out[:aead.NonceSize()]
	ciphertext := out[aead.NonceSize():]

	pt, err := aead.Open(nil, nonce2, ciphertext, head)
	if err != nil {
		log.Fatalf("open: %v", err)
	}

	fmt.Println(string(pt))
}
```

### ElGamal Exemplo de Uso (PHP)
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

### ElGamal Exemplo de Uso (Go)
```go
package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/pedroalbanese/eac/elgamal"
)

func main() {
	// Configuração de chaves
	x, _ := new(big.Int).SetString("2244f8d60ab7d1f907866c3388a522d2afed27c3a6fb3739c480d041d377174c", 16)
	p, g := elgamal.GetParameters()
	y := new(big.Int).Exp(g, x, p)

	// Mensagem de teste
	message := "Mensagem secreta para teste de criptografia e assinatura!"

	fmt.Println("=== Teste de Criptografia ElGamal ===")

	// 1. Criptografar
	pub := &elgamal.PublicKey{P: p, G: g, Y: y}
	c1, c2, err := elgamal.Encrypt(pub, []byte(message))
	if err != nil {
		log.Fatal("Erro ao criptografar:", err)
	}

	fmt.Printf("Mensagem original: %s\n", message)
	fmt.Println("Texto cifrado:")
	fmt.Printf("c1 = %x\n", c1)
	fmt.Printf("c2 = %x\n", c2)

	// 2. Descriptografar
	priv := &elgamal.PrivateKey{P: p, G: g, X: x}
	decrypted, err := elgamal.Decrypt(priv, c1, c2)
	if err != nil {
		log.Fatal("Erro ao descriptografar:", err)
	}

	fmt.Printf("\nMensagem descriptografada: %s\n", string(decrypted))

	// Verificação de criptografia
	if string(decrypted) == message {
		fmt.Println("✅ Criptografia/Descriptografia bem-sucedida!\n")
	} else {
		fmt.Println("❌ Erro na criptografia/descriptografia!\n")
	}

	fmt.Println("=== Teste de Assinatura Digital ElGamal ===")

	// 1. Gerar assinatura
	r, s, err := elgamal.Sign(priv, []byte(message))
	if err != nil {
		log.Fatal("Erro ao gerar assinatura:", err)
	}

	fmt.Println("Assinatura gerada:")
	fmt.Printf("r = %x\n", r)
	fmt.Printf("s = %x\n", s)

	// 2. Verificar assinatura
	valid, err := elgamal.Verify(pub, []byte(message), r, s)
	if err != nil {
		log.Fatal("Erro ao verificar assinatura:", err)
	}

	if valid {
		fmt.Println("✅ Assinatura válida!")
	} else {
		fmt.Println("❌ Assinatura inválida!")
	}

	fmt.Println("\n=== Teste Completo Concluído ===")
}
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
