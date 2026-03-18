#!/usr/bin/env php
<?php
/**
 * Wallet simulada para testing OID4VP.
 *
 * Simula el comportamiento de una EUDI Wallet:
 *   1. GET /request_uri/{id} — descarga el JWT Authorization Request (JAR)
 *   2. Construye un VC (EducationalID) y una VP firmados con ES256
 *   3. POST /direct_post — envia la VP al verificador
 *
 * Uso:
 *   php test_wallet.php <request_uri_url>
 *
 * Ejemplo:
 *   php test_wallet.php "https://idp.example.org/simplesaml/module.php/oid4vp/request_uri/550e8400-..."
 *
 * Requisitos:
 *   composer require firebase/php-jwt (ya incluido en el modulo)
 */

declare(strict_types=1);

// Try autoload from module, then from SSP root
$autoloads = [
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../../../../vendor/autoload.php',
];
$loaded = false;
foreach ($autoloads as $autoload) {
    if (file_exists($autoload)) {
        require_once $autoload;
        $loaded = true;
        break;
    }
}
if (!$loaded) {
    echo "ERROR: No se encontro vendor/autoload.php\n";
    echo "Ejecuta 'composer install' en el directorio del modulo primero.\n";
    exit(1);
}

use Firebase\JWT\JWT;

// ---------- Configuracion del test ----------

$credentialSubject = [
    'id'                         => 'did:key:zTestHolder456',
    'eduPersonPrincipalName'     => 'jgarcia@universidad.es',
    'schacHomeOrganization'      => 'universidad.es',
    'eduPersonScopedAffiliation' => 'student@universidad.es',
    'eduPersonPrimaryAffiliation'=> 'student',
    'eduPersonAffiliation'       => 'student',
    'eduPersonAssurance'         => 'https://refeds.org/assurance/IAP/low',
    'displayName'                => 'Juan Garcia Lopez',
    'commonName'                 => 'Juan Garcia Lopez',
    'familyName'                 => 'Garcia Lopez',
    'firstName'                  => 'Juan',
    'mail'                       => 'jgarcia@universidad.es',
    'schacPersonalUniqueCode'    => 'urn:schac:personalUniqueCode:int:esi:' . md5('jgarcia@universidad.es'),
    'identifier'                 => 'jgarcia',
];

$issuerDid = 'did:key:zTestIssuer123';
$holderDid = 'did:key:zTestHolder456';

// ---------- Argument parsing ----------

if ($argc < 2) {
    echo "Uso: php test_wallet.php <request_uri_url>\n\n";
    echo "El request_uri_url se obtiene del QR code generado por el modulo OID4VP.\n";
    echo "Puedes encontrarlo en la consola JS del navegador: window.oid4vpConfig.openidUri\n";
    echo "Extrae la parte despues de 'request_uri='.\n";
    exit(1);
}

$requestUriUrl = $argv[1];

// Optional: skip SSL verification for local testing
$skipSsl = in_array('--insecure', $argv) || in_array('-k', $argv);

echo "\n";
echo "=========================================\n";
echo "  EUDI Wallet Simulada - Test OID4VP\n";
echo "=========================================\n\n";

// ---------- Paso 1: GET request_uri ----------

echo "--- Paso 1: Descargar JWT Authorization Request (JAR) ---\n";
echo "GET $requestUriUrl\n\n";

$ch = curl_init($requestUriUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/oauth-authz-req+jwt']);
if ($skipSsl) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
}
$jarJwt = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

if ($httpCode !== 200) {
    echo "ERROR: HTTP $httpCode\n";
    if ($curlError) echo "curl error: $curlError\n";
    echo "Respuesta: $jarJwt\n";
    exit(1);
}

echo "JAR recibido (" . strlen($jarJwt) . " bytes)\n";

// Decode JAR payload (without verification — we're the test wallet)
$jarParts = explode('.', $jarJwt);
if (count($jarParts) !== 3) {
    echo "ERROR: JAR no es un JWT valido (partes: " . count($jarParts) . ")\n";
    exit(1);
}

$jarPayload = json_decode(base64_decode(strtr($jarParts[1], '-_', '+/')), true);
if ($jarPayload === null) {
    echo "ERROR: No se pudo decodificar el payload del JAR\n";
    exit(1);
}

echo "\nClaims del JAR:\n";
echo "  iss:           " . ($jarPayload['iss'] ?? '-') . "\n";
echo "  aud:           " . ($jarPayload['aud'] ?? '-') . "\n";
echo "  response_type: " . ($jarPayload['response_type'] ?? '-') . "\n";
echo "  response_mode: " . ($jarPayload['response_mode'] ?? '-') . "\n";
echo "  response_uri:  " . ($jarPayload['response_uri'] ?? '-') . "\n";
echo "  nonce:         " . substr($jarPayload['nonce'] ?? '-', 0, 20) . "...\n";
echo "  state:         " . substr($jarPayload['state'] ?? '-', 0, 20) . "...\n";
echo "  iat:           " . date('Y-m-d H:i:s', $jarPayload['iat'] ?? 0) . "\n";
echo "  exp:           " . date('Y-m-d H:i:s', $jarPayload['exp'] ?? 0) . "\n";
echo "\n";

$nonce = $jarPayload['nonce'] ?? null;
$state = $jarPayload['state'] ?? null;
$responseUri = $jarPayload['response_uri'] ?? null;
$verifierId = $jarPayload['iss'] ?? null;

if (!$nonce || !$state || !$responseUri) {
    echo "ERROR: JAR incompleto (falta nonce, state o response_uri)\n";
    exit(1);
}

// ---------- Paso 2: Construir VC + VP ----------

echo "--- Paso 2: Construir VC (EducationalID) + VP ---\n";

// Generate ephemeral EC P-256 keys
$issuerKey = openssl_pkey_new([
    'curve_name' => 'prime256v1',
    'private_key_type' => OPENSSL_KEYTYPE_EC,
]);
$holderKey = openssl_pkey_new([
    'curve_name' => 'prime256v1',
    'private_key_type' => OPENSSL_KEYTYPE_EC,
]);

if ($issuerKey === false || $holderKey === false) {
    echo "ERROR: No se pudieron generar claves EC P-256\n";
    echo "Asegurate de que ext-openssl esta instalado con soporte EC.\n";
    exit(1);
}

$now = time();

// Build VC JWT
$vcPayload = [
    'iss' => $issuerDid,
    'sub' => $holderDid,
    'iat' => $now,
    'exp' => $now + 86400,
    'vc' => [
        '@context' => ['https://www.w3.org/2018/credentials/v1'],
        'type' => ['VerifiableCredential', 'VerifiableEducationalID'],
        'issuer' => $issuerDid,
        'issuanceDate' => date('c', $now),
        'credentialSubject' => $credentialSubject,
    ],
];

$vcJwt = JWT::encode($vcPayload, $issuerKey, 'ES256', null, [
    'alg' => 'ES256',
    'typ' => 'JWT',
    'kid' => $issuerDid . '#key-1',
]);

echo "VC JWT generado (" . strlen($vcJwt) . " bytes)\n";
echo "  Issuer:  $issuerDid\n";
echo "  Tipo:    VerifiableEducationalID\n";
echo "  Subject: " . $credentialSubject['eduPersonPrincipalName'] . "\n";

// Build VP JWT wrapping the VC
$vpPayload = [
    'iss' => $holderDid,
    'aud' => $verifierId,
    'nonce' => $nonce,
    'iat' => $now,
    'exp' => $now + 300,
    'vp' => [
        '@context' => ['https://www.w3.org/2018/credentials/v1'],
        'type' => ['VerifiablePresentation'],
        'verifiableCredential' => [$vcJwt],
    ],
];

$vpJwt = JWT::encode($vpPayload, $holderKey, 'ES256', null, [
    'alg' => 'ES256',
    'typ' => 'JWT',
    'kid' => $holderDid . '#key-1',
]);

echo "VP JWT generado (" . strlen($vpJwt) . " bytes)\n";
echo "  Holder:  $holderDid\n";
echo "  Aud:     $verifierId\n";
echo "  Nonce:   " . substr($nonce, 0, 20) . "...\n";

// Presentation submission
$presentationSubmission = json_encode([
    'id' => 'test-submission-' . bin2hex(random_bytes(4)),
    'definition_id' => 'educationalid-presentation',
    'descriptor_map' => [
        [
            'id' => 'educationalid-descriptor',
            'format' => 'jwt_vp',
            'path' => '$',
            'path_nested' => [
                'format' => 'jwt_vc',
                'path' => '$.vp.verifiableCredential[0]',
            ],
        ],
    ],
]);

echo "\n";

// ---------- Paso 3: POST direct_post ----------

echo "--- Paso 3: POST direct_post ---\n";
echo "POST $responseUri\n";
echo "  vp_token: <" . strlen($vpJwt) . " bytes>\n";
echo "  state:    " . substr($state, 0, 20) . "...\n";
echo "  presentation_submission: <json>\n\n";

$ch = curl_init($responseUri);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'vp_token' => $vpJwt,
    'presentation_submission' => $presentationSubmission,
    'state' => $state,
]));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
if ($skipSsl) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
}
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

echo "Respuesta: HTTP $httpCode\n";
if ($curlError) {
    echo "curl error: $curlError\n";
}

$responseData = json_decode($response, true);
if ($responseData) {
    echo json_encode($responseData, JSON_PRETTY_PRINT) . "\n";
} else {
    echo "$response\n";
}

echo "\n";

// ---------- Resultado ----------

if ($httpCode === 200 && isset($responseData['status']) && $responseData['status'] === 'ok') {
    echo "=========================================\n";
    echo "  RESULTADO: EXITO\n";
    echo "=========================================\n\n";
    echo "La VP fue verificada correctamente.\n";
    echo "El navegador deberia detectar 'completed' en el siguiente\n";
    echo "ciclo de polling y completar la autenticacion SAML.\n\n";
    echo "Atributos enviados en el EducationalID:\n";
    foreach ($credentialSubject as $k => $v) {
        if ($k === 'id') continue;
        echo "  $k => $v\n";
    }
    echo "\n";
} else {
    echo "=========================================\n";
    echo "  RESULTADO: ERROR\n";
    echo "=========================================\n\n";
    if (isset($responseData['error_description'])) {
        echo "Descripcion: " . $responseData['error_description'] . "\n";
    }
    echo "Revisa los logs de SimpleSAMLphp para mas detalles:\n";
    echo "  tail -f /var/log/simplesamlphp/simplesamlphp.log | grep OID4VP\n\n";
    exit(1);
}
