<?php


class TOTP
{
    private static $charset = '23456789BCDFGHJKMNPQRTVWXY';
    const BITS_5_RIGHT = 31;
    const CHARS = 'abcdefghijklmnopqrstuvwxyz234567'; // lower-case
    public static function base32_decode($data)
    {
        $data = rtrim($data, "=\x20\t\n\r\0\x0B");
        $dataSize = strlen($data);
        $buf = 0;
        $bufSize = 0;
        $res = '';
        $charMap = array_flip(str_split(static::CHARS)); // char=>value map
        $charMap += array_flip(str_split(strtoupper(static::CHARS))); // add upper-case alternatives

        for ($i = 0; $i < $dataSize; $i++) {
            $c = $data[$i];
            if (!isset($charMap[$c])) {
                if ($c == " " || $c == "\r" || $c == "\n" || $c == "\t")
                    continue; // ignore these safe characters
                throw new Exception('Encoded string contains unexpected char #' . ord($c) . " at offset $i (using improper alphabet?)");
            }
            $b = $charMap[$c];
            $buf = ($buf << 5) | $b;
            $bufSize += 5;
            if ($bufSize > 7) {
                $bufSize -= 8;
                $b = ($buf & (0xff << $bufSize)) >> $bufSize;
                $res .= chr($b);
            }
        }

        return $res;
    }
    private static function generate($pub_key, array $time = null)
    {
        // STEP 1 generate hex
        if (!$time) {
            $aligned_time = time();
            $c =  pack('J', intval($aligned_time / 30));
        } else {
        }
        $res = hash_hmac('sha1', $c, $pub_key);
        // STEP 2 find index from $res
        $offset = 2 * (hexdec($res[-1]) & 0xF);
        $codeint = 0;
        for ($i = $offset; $i < $offset + 8; $i++) {
            $codeint += hexdec($res[$i]) << ($offset + 7 - $i) * 4;
        }
        $codeint &= 0x7fffffff;
        return $codeint;
    }

    public static function generate_code($pub_key, int $length)
    {
        $codeint = self::generate(self::base32_decode($pub_key));
        $str = str_pad($codeint, $length, "0", STR_PAD_LEFT);
        return substr($str, (-1 * $length));
    }
    public static function generate_steam_code($pub_key)
    {
        // steam要求base64解密
        $codeint = self::generate(base64_decode($pub_key));
        echo $codeint;
        $code = '';
        for ($i = 0; $i < 5; $i++) {
            $j = $codeint - intval($codeint / 26) * 26;
            $codeint = intval($codeint / 26);
            $code .= self::$charset[$j];
        }
        return $code;
    }
    public static function valid_code($pub_key)
    {
        $codeint[] = self::generate(base64_decode($pub_key));
    }
}

//echo TOTP::generate_steam_code("CJDa\\/1h8X6n+VzvT1J8nmEdEpuw=");
echo TOTP::generate_code("TwYr6W8ZAMnMszBHE1Xx", 6);