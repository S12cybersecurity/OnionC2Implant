<?php

class AES256Decryptor {
    private $sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ];

    private $invSbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ];

    private $rcon = [
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
    ];

    private $roundKey = [];
    private $Nr = 14;
    private $Nk = 8;
    private $Nb = 4;

    public function __construct($keyStr) {
        // Manejo de clave idéntico a C++
        if (strlen($keyStr) < 32) {
            $key = str_pad($keyStr, 32, "\0", STR_PAD_RIGHT);
        } elseif (strlen($keyStr) > 32) {
            $key = substr($keyStr, 0, 32);
            for ($i = 32; $i < strlen($keyStr); $i++) {
                $key[$i % 32] = chr(ord($key[$i % 32]) ^ ord($keyStr[$i]));
            }
        } else {
            $key = $keyStr;
        }

        $this->keyExpansion($key);
    }

    private function subWord($word) {
        $result = 0;
        for ($i = 0; $i < 4; $i++) {
            $byte = ($word >> (24 - 8*$i)) & 0xFF;
            $result |= ($this->sbox[$byte] << (24 - 8*$i));
        }
        return $result;
    }

    private function rotWord($word) {
        return (($word << 8) | (($word >> 24) & 0xFF)) & 0xFFFFFFFF;
    }

    private function keyExpansion($key) {
        $this->roundKey = array_fill(0, 4 * ($this->Nr + 1), 0);

        for ($i = 0; $i < $this->Nk; $i++) {
            $this->roundKey[$i] =
                (ord($key[4*$i])   << 24) |
                (ord($key[4*$i+1]) << 16) |
                (ord($key[4*$i+2]) << 8)  |
                ord($key[4*$i+3]);
        }

        for ($i = $this->Nk; $i < 4 * ($this->Nr + 1); $i++) {
            $temp = $this->roundKey[$i-1];

            if ($i % $this->Nk == 0) {
                $temp = $this->subWord($this->rotWord($temp)) ^ $this->rcon[intval($i / $this->Nk)];
            } elseif ($this->Nk > 6 && $i % $this->Nk == 4) {
                $temp = $this->subWord($temp);
            }

            $this->roundKey[$i] = ($this->roundKey[$i - $this->Nk] ^ $temp) & 0xFFFFFFFF;
        }
    }

    private function gMul($a, $b) {
        $p = 0;
        for ($counter = 0; $counter < 8; $counter++) {
            if (($b & 1) == 1) $p ^= $a;
            $hi_bit_set = $a & 0x80;
            $a = ($a << 1) & 0xFF;
            if ($hi_bit_set == 0x80) $a ^= 0x1b;
            $b >>= 1;
        }
        return $p;
    }

    // --------- DECRYPT (inverse) transforms ---------

    private function invSubBytes(&$state) {
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $state[$i][$j] = $this->invSbox[$state[$i][$j]];
            }
        }
    }

    private function invShiftRows(&$state) {
        for ($i = 1; $i < 4; $i++) {
            for ($j = 0; $j < $i; $j++) {
                $temp = $state[$i][3];
                for ($k = 3; $k > 0; $k--) {
                    $state[$i][$k] = $state[$i][$k-1];
                }
                $state[$i][0] = $temp;
            }
        }
    }

    private function invMixColumns(&$state) {
        for ($i = 0; $i < 4; $i++) {
            $s0 = $state[0][$i];
            $s1 = $state[1][$i];
            $s2 = $state[2][$i];
            $s3 = $state[3][$i];

            $state[0][$i] = $this->gMul(0x0e, $s0) ^ $this->gMul(0x0b, $s1) ^
                            $this->gMul(0x0d, $s2) ^ $this->gMul(0x09, $s3);
            $state[1][$i] = $this->gMul(0x09, $s0) ^ $this->gMul(0x0e, $s1) ^
                            $this->gMul(0x0b, $s2) ^ $this->gMul(0x0d, $s3);
            $state[2][$i] = $this->gMul(0x0d, $s0) ^ $this->gMul(0x09, $s1) ^
                            $this->gMul(0x0e, $s2) ^ $this->gMul(0x0b, $s3);
            $state[3][$i] = $this->gMul(0x0b, $s0) ^ $this->gMul(0x0d, $s1) ^
                            $this->gMul(0x09, $s2) ^ $this->gMul(0x0e, $s3);
        }
    }

    private function addRoundKey(&$state, $round) {
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $state[$j][$i] ^= ($this->roundKey[$round * 4 + $i] >> (24 - 8*$j)) & 0xFF;
            }
        }
    }

    private function decryptBlock(&$state) {
        $this->addRoundKey($state, $this->Nr);

        for ($round = $this->Nr - 1; $round >= 1; $round--) {
            $this->invShiftRows($state);
            $this->invSubBytes($state);
            $this->addRoundKey($state, $round);
            $this->invMixColumns($state);
        }

        $this->invShiftRows($state);
        $this->invSubBytes($state);
        $this->addRoundKey($state, 0);
    }

    // --------- ENCRYPT (forward) transforms ---------

    private function subBytes(&$state) {
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $state[$i][$j] = $this->sbox[$state[$i][$j]];
            }
        }
    }

    private function shiftRows(&$state) {
        for ($i = 1; $i < 4; $i++) {
            for ($j = 0; $j < $i; $j++) {
                $temp = $state[$i][0];
                $state[$i][0] = $state[$i][1];
                $state[$i][1] = $state[$i][2];
                $state[$i][2] = $state[$i][3];
                $state[$i][3] = $temp;
            }
        }
    }

    private function mixColumns(&$state) {
        for ($i = 0; $i < 4; $i++) {
            $s0 = $state[0][$i];
            $s1 = $state[1][$i];
            $s2 = $state[2][$i];
            $s3 = $state[3][$i];

            $state[0][$i] = $this->gMul(0x02, $s0) ^ $this->gMul(0x03, $s1) ^ $s2 ^ $s3;
            $state[1][$i] = $s0 ^ $this->gMul(0x02, $s1) ^ $this->gMul(0x03, $s2) ^ $s3;
            $state[2][$i] = $s0 ^ $s1 ^ $this->gMul(0x02, $s2) ^ $this->gMul(0x03, $s3);
            $state[3][$i] = $this->gMul(0x03, $s0) ^ $s1 ^ $s2 ^ $this->gMul(0x02, $s3);
        }
    }

    private function encryptBlock(&$state) {
        $this->addRoundKey($state, 0);

        for ($round = 1; $round < $this->Nr; $round++) {
            $this->subBytes($state);
            $this->shiftRows($state);
            $this->mixColumns($state);
            $this->addRoundKey($state, $round);
        }

        $this->subBytes($state);
        $this->shiftRows($state);
        $this->addRoundKey($state, $this->Nr);
    }

    // --------- PUBLIC API ---------

    // Compatible con AES256Encryptor de C++ (PKCS7, orden state igual)
    public function encrypt($plaintext) {
        if ($plaintext === null) {
            throw new Exception("Plaintext cannot be null");
        }

        $data = array_values(unpack('C*', $plaintext));

        // PKCS7 padding
        $padLen = 16 - (count($data) % 16);
        for ($i = 0; $i < $padLen; $i++) {
            $data[] = $padLen;
        }

        $cipherBytes = [];

        for ($i = 0; $i < count($data); $i += 16) {
            $state = [];

            // PLAINTEXT -> STATE (column-major, igual que C++)
            for ($j = 0; $j < 4; $j++) {
                $state[$j] = [];
                for ($k = 0; $k < 4; $k++) {
                    $state[$j][$k] = $data[$i + $j + 4*$k];
                }
            }

            $this->encryptBlock($state);

            // STATE -> CIPHERTEXT (row-major, igual que C++)
            for ($j = 0; $j < 4; $j++) {
                for ($k = 0; $k < 4; $k++) {
                    $cipherBytes[] = $state[$j][$k];
                }
            }
        }

        // bytes -> hex
        $hex = '';
        foreach ($cipherBytes as $b) {
            $hex .= str_pad(dechex($b & 0xFF), 2, '0', STR_PAD_LEFT);
        }

        return $hex;
    }

    // Compatible con AES256Encryptor de C++ (PKCS7, orden state inverso)
    public function decrypt($hexCiphertext) {
        if (empty($hexCiphertext)) {
            throw new Exception("Ciphertext cannot be empty");
        }

        $ciphertext = @hex2bin($hexCiphertext);
        if ($ciphertext === false) {
            throw new Exception("Invalid hexadecimal format");
        }

        if (strlen($ciphertext) % 16 !== 0) {
            throw new Exception("Invalid ciphertext length");
        }

        $plaintext = '';

        for ($i = 0; $i < strlen($ciphertext); $i += 16) {
            $state = [];

            // CIPHERTEXT -> STATE (row-major, igual que lo escribió C++)
            for ($j = 0; $j < 4; $j++) {
                $state[$j] = [];
                for ($k = 0; $k < 4; $k++) {
                    $state[$j][$k] = ord($ciphertext[$i + 4*$j + $k]);
                }
            }

            $this->decryptBlock($state);

            // STATE -> PLAINTEXT (column-major, igual que lo lee C++)
            for ($k = 0; $k < 4; $k++) {
                for ($j = 0; $j < 4; $j++) {
                    $plaintext .= chr($state[$j][$k]);
                }
            }
        }

        // Remover padding PKCS7
        $padLen = ord($plaintext[strlen($plaintext) - 1]);
        if ($padLen > 0 && $padLen <= 16) {
            $valid = true;
            for ($i = 0; $i < $padLen; $i++) {
                if (ord($plaintext[strlen($plaintext) - 1 - $i]) !== $padLen) {
                    $valid = false;
                    break;
                }
            }
            if ($valid) {
                $plaintext = substr($plaintext, 0, -$padLen);
            }
        }

        return $plaintext;
    }

    public static function getEncryptionandDecryptionKeysByUUID($uuid) {
        if (empty($uuid)) {
            return [
                'success' => false,
                'error' => 'UUID is required'
            ];
        }

        try {
            $mongoUri = getenv('MONGO_URI');
            if (empty($mongoUri)) {
                throw new Exception("MongoDB URI not configured in environment variables");
            }

            $manager = new MongoDB\Driver\Manager($mongoUri, ['connectTimeoutMS' => 5000]);

            $filter = ['uuid' => $uuid];
            $options = [
                'projection' => [
                    'encryption_key' => 1,
                    'decryption_key' => 1,
                    'uuid' => 1,
                    '_id' => 0
                ]
            ];

            $query = new MongoDB\Driver\Query($filter, $options);
            $cursor = $manager->executeQuery('c2_redirector.payloads', $query);
            $documents = $cursor->toArray();

            if (empty($documents)) {
                return [
                    'success' => false,
                    'error' => 'No payload found for UUID: ' . $uuid
                ];
            }

            $payload = $documents[0];

            return [
                'success' => true,
                'uuid' => $payload->uuid,
                'encryption_key' => $payload->encryption_key ?? null,
                'decryption_key' => $payload->decryption_key ?? null
            ];

        } catch (MongoDB\Driver\Exception\Exception $e) {
            return [
                'success' => false,
                'error' => 'MongoDB error: ' . $e->getMessage()
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Error: ' . $e->getMessage()
            ];
        }
    }
}

?>
