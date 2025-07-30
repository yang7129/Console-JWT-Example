using Console_JWT_Example.JWT;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Console_JWT_Example.JWS
{
    internal class JWS : Base
    {
        public void exmple_HMACSHA_256()
        {
            //Example JWS Using HMAC SHA - 256 
            Console.WriteLine("exmple_HMACSHA_256");
            // JWS  https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A
            // JWS = eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
            // Header = {"typ":"JWT","alg":"HS256"}
            // Payload ={"iss":"joe","exp":1300819380,"http://example.com/is_root":true}
            // Key =  {"kty":"oct", "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

            string headerJson = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
            //  encodedHeader = eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
            string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));

            string encodedHeader_expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
            Console.WriteLine("Check？encodedHeader=encodedHeader_expected |" + (encodedHeader == encodedHeader_expected));
            // Decode JWT Headjson
            //Console.WriteLine(Base64UrlDecodeToString("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"));

            string payloadJson = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
            // encodedPayload = eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
            string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string encodedPayload_expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
            Console.WriteLine("Check？encodedPayload=encodedPayload_expected |" + (encodedPayload == encodedPayload_expected));
            // Decode JWT payloadJson
            //Console.WriteLine(Base64UrlDecodeToString("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"));

            // encodedHeader.encodedPayload
            string signingInput = $"{encodedHeader}.{encodedPayload}";

            string key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
            byte[] keyBytes = Base64UrlDecode(key);

            byte[] signatureBytes;
            using (var hmac = new HMACSHA256(keyBytes))
            {
                signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput));
            }
            string encodedSignature = Base64UrlEncode(signatureBytes);
            // encodedHeader.encodedPayload.encodedSignature
            string JWS = $"{signingInput}.{encodedSignature}";
            Console.WriteLine("JWS:");
            Console.WriteLine(JWS);
            string expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

            Console.WriteLine("Check？JWS=expected |" + (JWS == expected));




        }
        public void exmple_HMACSHA_256_3DES_ECB() 
        {
            //1.Header
            string header = "{\"alg\":\"HS256\"}";
            string headerBase64Url = Base64UrlEncode(header);
            Console.WriteLine("header|" + headerBase64Url);
            Console.WriteLine("Check|header|" + (headerBase64Url.Equals("eyJhbGciOiJIUzI1NiJ9")));

            //2. payload 
            string payload = "Test JWS exmple_HMACSHA_256_3DES_ECB ";
            var payloadBase64Url = Base64UrlEncode(payload);
            Console.WriteLine("payload|" + payloadBase64Url); 
            // 組合頭跟身體  JWS = Header.Payload.Signature
            string HeaderstrPayloadstr = headerBase64Url + "." + payloadBase64Url;
            //3.
            //Random get 32BYTE   
            byte[] RandomData = new byte[32]; // 
            RandomNumberGenerator.Fill(RandomData); 
            string RandomDataHexString = BytesToHexString(RandomData);

            //4 //這邊取得ABCODE資訊
            byte[] RandomAcode = new byte[16]; 
            RandomNumberGenerator.Fill(RandomAcode);
            byte[] bytesA = HexStringToBytes(BytesToHexString(RandomAcode));  
            byte[] RandomBcode = new byte[16];
            RandomNumberGenerator.Fill(RandomBcode);
            byte[] bytesB = HexStringToBytes(BytesToHexString(RandomBcode)); 
            //合體 A XOR B
            byte[] clearKeyBytes = XorBytes(bytesA, bytesB);
            string clearKeyHex = BytesToHexString(clearKeyBytes);
            Console.WriteLine("clearKeyHex|" + clearKeyHex);
            // 使用 Clear Key 作為 seed key 進行 3DES ECB 加密
            byte[] macKeyBinary = Encrypt3DES(clearKeyBytes, RandomData, new byte[8], CipherMode.ECB, PaddingMode.Zeros);
            string macKeyHex = BytesToHexString(macKeyBinary);
            byte[] hmacKeyK = HexStringToBytes(macKeyHex.PadRight(128, '0'));  
            byte[] jwsInputDataBytes = Encoding.UTF8.GetBytes(HeaderstrPayloadstr); // HMAC 運算是對原始位元組進行的
            // 計算 HMAC-SHA256
            byte[] jwsSignatureBytes = ComputeHmacSha256(hmacKeyK, jwsInputDataBytes);
            //string jwsSignatureHex = BytesToHexString(jwsSignatureBytes); 
            // --- 5. 對步驟 8 所產出的簽章值進行 BASE64URL 編碼 ---
            string JwsSignatureBase64Url = Base64UrlEncode(jwsSignatureBytes);
            Console.WriteLine("Check|JwsSignatureBase64Url|" + JwsSignatureBase64Url);  

        }
        public byte[] Encrypt3DES(byte[] key, byte[] dataToEncrypt, byte[] iv, CipherMode cipherMode, PaddingMode paddingMode)
        {
            byte[] desKey;
            // 檢查金鑰長度並處理
            if (key.Length == 16) // 如果是 16 位元組 (2-Key 3DES)
            {
                desKey = new byte[24];
                Buffer.BlockCopy(key, 0, desKey, 0, 16); // 複製 K1 和 K2
                Buffer.BlockCopy(key, 0, desKey, 16, 8); // K3 = K1 (複製 K1 的前 8 位元組)
                Console.WriteLine($"偵測到 16 位元組bytes金鑰，已擴展Add為= 24 位元組 (K1|K2|K1)。");
                Console.WriteLine($"擴展後的金鑰 (Hex): {BytesToHexString(desKey)}");
            }
            else if (key.Length == 24) // 如果是 24 位元組 (3-Key 3DES)
            {
                desKey = key;
            }
            else
            {
                throw new ArgumentException("3DES 金鑰長度Len必須是= 16 或or 24 位元組bytes。", nameof(key));
            }
            using (TripleDES des = TripleDES.Create())
            {
                des.Key = desKey;
                des.Mode = cipherMode;// CipherMode.ECB;
                des.Padding = paddingMode;// PaddingMode.Zeros;
                des.IV = iv; 
                using (ICryptoTransform encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
                }
            }
        }
        public byte[] ComputeSha256Hash(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }
        public byte[] ComputeHmacSha256(byte[] key, byte[] input)
        {
            int blockSize = 64; // SHA-256 的區塊大小為 64 位元組

            // K 為 HMAC 的 Key 值，即為步驟 7 之 mac key，當 Key 長度小於 64 時，將後補 0x00 至長度 64。
            byte[] K_padded = new byte[blockSize];
            Array.Copy(key, K_padded, Math.Min(key.Length, blockSize));
            // 如果 key.Length < blockSize，Array.Copy 會自動用 0x00 填充剩餘部分 (因為 byte 陣列預設值為 0)

            // ipad 為 64 個 0x36
            byte[] ipad = new byte[blockSize];
            Array.Fill(ipad, (byte)0x36);

            // opad 為 64 個 0x5C
            byte[] opad = new byte[blockSize];
            Array.Fill(opad, (byte)0x5C);

            // K XOR ipad
            byte[] k_xor_ipad = XorBytes(K_padded, ipad);

            // K XOR opad
            byte[] k_xor_opad = XorBytes(K_padded, opad);

            // H(K XOR ipad || Input)
            // 結合 k_xor_ipad 和 input
            byte[] innerHashInput = new byte[k_xor_ipad.Length + input.Length];
            Buffer.BlockCopy(k_xor_ipad, 0, innerHashInput, 0, k_xor_ipad.Length);
            Buffer.BlockCopy(input, 0, innerHashInput, k_xor_ipad.Length, input.Length);

            byte[] innerHashResult = ComputeSha256Hash(innerHashInput);

            // H(K XOR opad || H(K XOR ipad || Input))
            // 結合 k_xor_opad 和 innerHashResult
            byte[] outerHashInput = new byte[k_xor_opad.Length + innerHashResult.Length];
            Buffer.BlockCopy(k_xor_opad, 0, outerHashInput, 0, k_xor_opad.Length);
            Buffer.BlockCopy(innerHashResult, 0, outerHashInput, k_xor_opad.Length, innerHashResult.Length);

            byte[] hmacResult = ComputeSha256Hash(outerHashInput);
            return hmacResult;
        }
    }
}
