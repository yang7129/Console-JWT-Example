using Org.BouncyCastle.Ocsp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Console_JWT_Example.RFC8017
{
    internal class RFC8017 : Base
    {
        public void exmple_RFC8017() {

            Console.WriteLine("exmple_RFC8017");
            Console.WriteLine("RSA_OAEP_SHA256_MGF1SHA1");
            //檔案讀取 Read public.pem   private.pem 
            string publicKeyPath = Path.Combine("key", "public.pem"); 
            string publicKey = File.OpenText(publicKeyPath).ReadToEnd();
            string privateKeyPath = Path.Combine("key", "private.pem");
            string privateKey = File.OpenText(privateKeyPath).ReadToEnd();
            string testtext = "This is Example By RFC8017";
            var encrypted = RSA_OAEP_SHA256_MGF1SHA1_Encrypt(testtext, publicKey);

            var decryptedResult = RSA_OAEP_SHA256_MGF1SHA1_Decrypt(encrypted, privateKey);
            //Verify
            Console.WriteLine("Check testtext == decryptedResult |" + decryptedResult.Equals(testtext));

            Console.WriteLine("exmple_RFC8017_End");


        }
        public static string RSA_OAEP_SHA256_MGF1SHA1_Encrypt(string plainText, string publicKeyPem)
        {
            ArgumentNullException.ThrowIfNull(plainText);
            ArgumentNullException.ThrowIfNull(publicKeyPem);

            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem.AsSpan());

            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var keySize = rsa.KeySize / 8;

            // SHA-256: hLen = 32, 最大明文長度 = keySize - 2*32 - 2
            var maxChunkSize = keySize - 2 * 32 - 2; // 190 bytes for 2048-bit key

            if (dataBytes.Length <= maxChunkSize)
            {
                var encrypted = EncryptSingleBlock(rsa, dataBytes);
                return Convert.ToBase64String(encrypted);
            }

            // 分段加密
            var encryptedChunks = new List<byte>();
            for (int i = 0; i < dataBytes.Length; i += maxChunkSize)
            {
                var chunkSize = Math.Min(maxChunkSize, dataBytes.Length - i);
                var chunk = new byte[chunkSize];
                Array.Copy(dataBytes, i, chunk, 0, chunkSize);

                var encryptedChunk = EncryptSingleBlock(rsa, chunk);
                encryptedChunks.AddRange(encryptedChunk);
            }

            return Convert.ToBase64String(encryptedChunks.ToArray());
        }

        /// <summary>
        /// 解密資料
        /// </summary>
        public static string RSA_OAEP_SHA256_MGF1SHA1_Decrypt(string encryptedBase64, string privateKeyPem)
        {
            ArgumentNullException.ThrowIfNull(encryptedBase64);
            ArgumentNullException.ThrowIfNull(privateKeyPem);

            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem.AsSpan());

            var encryptedBytes = Convert.FromBase64String(encryptedBase64);
            var keySize = rsa.KeySize / 8;

            if (encryptedBytes.Length <= keySize)
            {
                var decrypted = DecryptSingleBlock(rsa, encryptedBytes);
                return Encoding.UTF8.GetString(decrypted);
            }

            // 分段解密
            var decryptedChunks = new List<byte>();
            for (int i = 0; i < encryptedBytes.Length; i += keySize)
            {
                var chunkSize = Math.Min(keySize, encryptedBytes.Length - i);
                var chunk = new byte[chunkSize];
                Array.Copy(encryptedBytes, i, chunk, 0, chunkSize);

                var decryptedChunk = DecryptSingleBlock(rsa, chunk);
                decryptedChunks.AddRange(decryptedChunk);
            }

            return Encoding.UTF8.GetString(decryptedChunks.ToArray());
        }

        /// <summary>
        /// 單一區塊加密
        /// </summary>
        private static byte[] EncryptSingleBlock(RSA rsa, byte[] message)
        {
            const int SHA256_LENGTH = 32;
            var keySize = rsa.KeySize / 8;
            var label = Array.Empty<byte>();

            // 步驟 1: 計算 lHash (使用 SHA-256)
            byte[] lHash;
            using (var sha256 = SHA256.Create())
            {
                lHash = sha256.ComputeHash(label);
            }

            // 步驟 2: 產生填充
            var mLen = message.Length;
            var psLen = keySize - mLen - 2 * SHA256_LENGTH - 2;
            if (psLen < 0)
                throw new ArgumentException("Message too long");

            var ps = new byte[psLen]; // 全部為 0

            // 步驟 3: 建構 DB = lHash || PS || 0x01 || M
            var db = new byte[SHA256_LENGTH + psLen + 1 + mLen];
            var index = 0;

            Array.Copy(lHash, 0, db, index, SHA256_LENGTH);
            index += SHA256_LENGTH;

            Array.Copy(ps, 0, db, index, psLen);
            index += psLen;

            db[index++] = 0x01;
            Array.Copy(message, 0, db, index, mLen);

            // 步驟 4: 產生隨機種子
            var seed = new byte[SHA256_LENGTH];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(seed);
            }

            // 步驟 5: dbMask = MGF1-SHA1(seed, k - hLen - 1)
            var dbMask = MGF1_SHA1(seed, keySize - SHA256_LENGTH - 1);

            // 步驟 6: maskedDB = DB ⊕ dbMask
            var maskedDB = XOR(db, dbMask);

            // 步驟 7: seedMask = MGF1-SHA1(maskedDB, hLen)
            var seedMask = MGF1_SHA1(maskedDB, SHA256_LENGTH);

            // 步驟 8: maskedSeed = seed ⊕ seedMask
            var maskedSeed = XOR(seed, seedMask);

            // 步驟 9: EM = 0x00 || maskedSeed || maskedDB
            var em = new byte[keySize];
            index = 0;
            em[index++] = 0x00;
            Array.Copy(maskedSeed, 0, em, index, maskedSeed.Length);
            index += maskedSeed.Length;
            Array.Copy(maskedDB, 0, em, index, maskedDB.Length);

            // 步驟 10: RSA 加密 - 使用數學運算
            return RSAEncrypt(rsa, em);
        }

        /// <summary>
        /// 單一區塊解密
        /// </summary>
        private static byte[] DecryptSingleBlock(RSA rsa, byte[] ciphertext)
        {
            const int SHA256_LENGTH = 32;
            var keySize = rsa.KeySize / 8;
            var label = Array.Empty<byte>();

            // 步驟 1: RSA 解密 - 使用數學運算
            var em = RSADecrypt(rsa, ciphertext);

            if (em.Length != keySize)
                throw new CryptographicException("Decryption error");

            // 步驟 2: 分離 EM
            if (em[0] != 0x00)
                throw new CryptographicException("Decryption error");

            var maskedSeed = new byte[SHA256_LENGTH];
            var maskedDB = new byte[keySize - SHA256_LENGTH - 1];

            Array.Copy(em, 1, maskedSeed, 0, SHA256_LENGTH);
            Array.Copy(em, 1 + SHA256_LENGTH, maskedDB, 0, maskedDB.Length);

            // 步驟 3: seedMask = MGF1-SHA1(maskedDB, hLen)
            var seedMask = MGF1_SHA1(maskedDB, SHA256_LENGTH);

            // 步驟 4: seed = maskedSeed ⊕ seedMask
            var seed = XOR(maskedSeed, seedMask);

            // 步驟 5: dbMask = MGF1-SHA1(seed, k - hLen - 1)
            var dbMask = MGF1_SHA1(seed, keySize - SHA256_LENGTH - 1);

            // 步驟 6: DB = maskedDB ⊕ dbMask
            var db = XOR(maskedDB, dbMask);

            // 步驟 7: 驗證和分離 DB
            byte[] lHash;
            using (var sha256 = SHA256.Create())
            {
                lHash = sha256.ComputeHash(label);
            }

            // 驗證 lHash
            for (int i = 0; i < SHA256_LENGTH; i++)
            {
                if (db[i] != lHash[i])
                    throw new CryptographicException("Decryption error - lHash verification failed");
            }

            // 尋找 0x01 分隔符
            int separatorIndex = -1;
            for (int i = SHA256_LENGTH; i < db.Length; i++)
            {
                if (db[i] == 0x01)
                {
                    separatorIndex = i;
                    break;
                }
                if (db[i] != 0x00)
                    throw new CryptographicException("Decryption error - invalid padding");
            }

            if (separatorIndex == -1)
                throw new CryptographicException("Decryption error - separator not found");

            // 提取訊息
            var messageLength = db.Length - separatorIndex - 1;
            var message = new byte[messageLength];
            Array.Copy(db, separatorIndex + 1, message, 0, messageLength);

            return message;
        }

        /// <summary>
        /// RSA 加密運算
        /// </summary>
        private static byte[] RSAEncrypt(RSA rsa, byte[] data)
        {
            var parameters = rsa.ExportParameters(false);
            var n = new BigInteger(parameters.Modulus!, true, true);
            var e = new BigInteger(parameters.Exponent!, true, true);

            var m = new BigInteger(data, true, true);
            var c = BigInteger.ModPow(m, e, n);

            var result = c.ToByteArray(true, true);
            var keySize = rsa.KeySize / 8;

            // 確保結果長度等於金鑰大小
            if (result.Length < keySize)
            {
                var padded = new byte[keySize];
                Array.Copy(result, 0, padded, keySize - result.Length, result.Length);
                return padded;
            }
            else if (result.Length > keySize)
            {
                // 移除多餘的零位元組
                var trimmed = new byte[keySize];
                Array.Copy(result, result.Length - keySize, trimmed, 0, keySize);
                return trimmed;
            }

            return result;
        }

        /// <summary>
        /// RSA 解密運算
        /// </summary>
        private static byte[] RSADecrypt(RSA rsa, byte[] data)
        {
            var parameters = rsa.ExportParameters(true);
            var n = new BigInteger(parameters.Modulus!, true, true);
            var d = new BigInteger(parameters.D!, true, true);

            var c = new BigInteger(data, true, true);
            var m = BigInteger.ModPow(c, d, n);

            var result = m.ToByteArray(true, true);
            var keySize = rsa.KeySize / 8;

            // 確保結果長度等於金鑰大小
            if (result.Length < keySize)
            {
                var padded = new byte[keySize];
                Array.Copy(result, 0, padded, keySize - result.Length, result.Length);
                return padded;
            }
            else if (result.Length > keySize)
            {
                // 移除多餘的零位元組
                var trimmed = new byte[keySize];
                Array.Copy(result, result.Length - keySize, trimmed, 0, keySize);
                return trimmed;
            }

            return result;
        }

        /// <summary>
        /// MGF1 遮罩生成函數 (使用 SHA-1)
        /// </summary>
        private static byte[] MGF1_SHA1(byte[] seed, int maskLen)
        {
            const int SHA1_LENGTH = 20;

            if (maskLen >= (1L << 32) * SHA1_LENGTH)
                throw new ArgumentException("Mask too long");

            var mask = new byte[maskLen];
            var hashInput = new byte[seed.Length + 4];
            Array.Copy(seed, hashInput, seed.Length);

            using var sha1 = SHA1.Create();

            for (uint counter = 0; counter < (maskLen + SHA1_LENGTH - 1) / SHA1_LENGTH; counter++)
            {
                // Big-endian counter
                hashInput[seed.Length] = (byte)(counter >> 24);
                hashInput[seed.Length + 1] = (byte)(counter >> 16);
                hashInput[seed.Length + 2] = (byte)(counter >> 8);
                hashInput[seed.Length + 3] = (byte)counter;

                var hash = sha1.ComputeHash(hashInput);
                var copyLen = Math.Min(hash.Length, maskLen - (int)(counter * SHA1_LENGTH));
                Array.Copy(hash, 0, mask, (int)(counter * SHA1_LENGTH), copyLen);
            }

            return mask;
        }

        /// <summary>
        /// XOR 運算
        /// </summary>
        private static byte[] XOR(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException("Arrays must have same length");

            var result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }
    }
}
