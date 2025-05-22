using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters; 
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
namespace Console_JWT_Example.JWE
{
    internal class JWE : Base
    {
        public void exmple_AESKW_AES_128_CBC_HMAC_SHA_256()
        {
            //Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
            Console.WriteLine("exmple_AESKW_AES_128_CBC_HMAC_SHA_256");
            // JWE https://www.rfc-editor.org/rfc/rfc7516#page-41
            // JWE = eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ
            // IV = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101] // base64url AxY8DCtDaGlsbGljb3RoZQ
            // CEK = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207]
            // KEK =  {"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}
            // plaintext = "Live long and prosper."

            // IV
            byte[] IV = Base64UrlDecode("AxY8DCtDaGlsbGljb3RoZQ");
            //CEK
            byte[] CEK = new byte[] { 4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207 };
            //KEK
            byte[] KEK = Base64UrlDecode("GawgguFyGrWKav7AX4VKUg");

            //AES WK
            AesWrapEngine AesWK = new AesWrapEngine();
            AesWK.Init(true, new KeyParameter(KEK));
            byte[] EncryptedKey = AesWK.Wrap(CEK, 0, CEK.Length);

            byte[] HmacKey = new byte[16];
            byte[] AesKey = new byte[16];
            Array.Copy(CEK, 0, HmacKey, 0, 16);
            Array.Copy(CEK, 16, AesKey, 0, 16);

            string Plaintext = "Live long and prosper.";
            byte[] PlaintextByte = StringToBytes(Plaintext);

            //Cipher
            IBufferedCipher Cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
            Cipher.Init(true, new ParametersWithIV(new KeyParameter(AesKey), IV));
            byte[] Ciphertext = Cipher.DoFinal(PlaintextByte);

            //Aad
            string HeaderJson = "{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}";
            byte[] Aad = StringToBytes(Base64UrlEncode(HeaderJson));

            //Tag
            byte[] A1 = BitConverter.GetBytes((long)(Aad.Length * 8));
            if (BitConverter.IsLittleEndian) Array.Reverse(A1);

            byte[] AuthData = Combiner(Aad, IV, Ciphertext, A1);
            byte[] HmacFull = new HMACSHA256(HmacKey).ComputeHash(AuthData);
            byte[] Tag = new byte[16];
            Array.Copy(HmacFull, 0, Tag, 0, 16);

            string encodedHeader_expected = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
            Console.WriteLine("Check？encoded=encodedHeader_expected |" + (Base64UrlEncode(HeaderJson) == encodedHeader_expected));

            string EncryptedKey_expected = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ";
            Console.WriteLine("Check？encoded=EncryptedKey_expected |" + (Base64UrlEncode(EncryptedKey) == EncryptedKey_expected));

            string IV_expected = "AxY8DCtDaGlsbGljb3RoZQ";
            Console.WriteLine("Check？encoded=IV_expected |" + (Base64UrlEncode(IV) == IV_expected));

            string Ciphertext_expected = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
            Console.WriteLine("Check？encoded=Ciphertext_expected |" + (Base64UrlEncode(Ciphertext) == Ciphertext_expected));

            string Tag_expected = "U0m_YmjN04DJvceFICbCVQ";
            Console.WriteLine("Check？encoded=Tag_expected |" + (Base64UrlEncode(Tag) == Tag_expected));

            // Header.EncryptedKey.IV.Ciphertext.Tag
            string JWE = $"{Base64UrlEncode(HeaderJson)}.{Base64UrlEncode(EncryptedKey)}.{Base64UrlEncode(IV)}.{Base64UrlEncode(Ciphertext)}.{Base64UrlEncode(Tag)}";
            Console.WriteLine(JWE);
            string expected = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";

            Console.WriteLine("Check？JWE=expected |" + (JWE == expected));
            Console.WriteLine("Decrypt====================");
            // Decrypt 
            string DecryptJWE = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";
            string[] Parts = DecryptJWE.Split('.');

            string HeaderJsonDecrypt = Base64UrlDecodeToString(Parts[0]);
            Console.WriteLine("Check？ HeaderJsonDecrypt=HeaderJson |" + HeaderJsonDecrypt.Equals(HeaderJson));
            byte[] EncryptedKeyDecrypt = Base64UrlDecode(Parts[1]);
            Console.WriteLine("Check？ EncryptedKeyDecrypt=EncryptedKey |" + BytesToString(EncryptedKeyDecrypt).Equals(BytesToString(EncryptedKey)));
            byte[] IVDecrypt = Base64UrlDecode(Parts[2]);
            Console.WriteLine("Check？ IVDecrypt=IV |" + BytesToString(IVDecrypt).Equals(BytesToString(IV)));
            byte[] CiphertextDecrypt = Base64UrlDecode(Parts[3]);
            Console.WriteLine("Check？ CiphertextDecrypt=Ciphertext |" + BytesToString(CiphertextDecrypt).Equals(BytesToString(Ciphertext)));
            byte[] TagDecrypt = Base64UrlDecode(Parts[4]);
            Console.WriteLine("Check？ TagDecrypt=Tag |" + BytesToString(TagDecrypt).Equals(BytesToString(Tag)));

            byte[] KEKDecrypt = Base64UrlDecode("GawgguFyGrWKav7AX4VKUg");
            Console.WriteLine("Check？ KEKDecrypt=KEK |" + BytesToString(KEKDecrypt).Equals(BytesToString(KEK)));
            byte[] AadDecrypt = StringToBytes(Parts[0]);
            Console.WriteLine("Check？ AadDecrypt=Aad |" + BytesToString(AadDecrypt).Equals(BytesToString(Aad)));

            //AES WK Decrypt
            AesWrapEngine AesWKDecrypt = new AesWrapEngine();
            AesWKDecrypt.Init(false, new KeyParameter(KEKDecrypt));
            byte[] CEKDecrypt = AesWKDecrypt.Unwrap(EncryptedKeyDecrypt, 0, EncryptedKeyDecrypt.Length);
            Console.WriteLine("Check？ CEKDecrypt=CEK |" + BytesToString(CEKDecrypt).Equals(BytesToString(CEK)));

            byte[] HmacKeyDecrypt = new byte[16];
            byte[] AesKeyDecrypt = new byte[16];
            Array.Copy(CEKDecrypt, 0, HmacKeyDecrypt, 0, 16);
            Array.Copy(CEKDecrypt, 16, AesKeyDecrypt, 0, 16);
            Console.WriteLine("Check？ HmacKeyDecrypt=HmacKey |" + BytesToString(HmacKeyDecrypt).Equals(BytesToString(HmacKey)));
            Console.WriteLine("Check？ AesKeyDecrypt=AesKey |" + BytesToString(AesKeyDecrypt).Equals(BytesToString(AesKey)));

            //Tag
            byte[] A1Decrypt = BitConverter.GetBytes((long)(AadDecrypt.Length * 8));
            if (BitConverter.IsLittleEndian) Array.Reverse(A1Decrypt);

            byte[] AuthDataDecrypt = Combiner(AadDecrypt, IVDecrypt, CiphertextDecrypt, A1Decrypt);
            Console.WriteLine("Check？ AuthDataDecrypt=AuthData |" + BytesToString(AuthDataDecrypt).Equals(BytesToString(AuthData)));
            byte[] HmacFullDecrypt = new HMACSHA256(HmacKeyDecrypt).ComputeHash(AuthDataDecrypt);
            Console.WriteLine("Check？ HmacFullDecrypt=HmacFull |" + BytesToString(HmacFullDecrypt).Equals(BytesToString(HmacFull)));
            for (int i = 0; i < 16; i++)
            {
                if (!HmacFullDecrypt[i].Equals(TagDecrypt[i]))
                {
                    Console.WriteLine("解密失敗|");
                    return;
                }
            }
            var AesDecrypt = Aes.Create();
            AesDecrypt.Mode = CipherMode.CBC;
            AesDecrypt.Padding = PaddingMode.PKCS7;
            AesDecrypt.Key = AesKeyDecrypt;
            AesDecrypt.IV = IVDecrypt;

            byte[] PlaintextByteDecrypt;
            using (var AesDecryptor = AesDecrypt.CreateDecryptor())
            {
                PlaintextByteDecrypt = AesDecryptor.TransformFinalBlock(CiphertextDecrypt, 0, CiphertextDecrypt.Length);
            }
            string PlaintextDecrypt = BytesToString(PlaintextByteDecrypt);
            Console.WriteLine("Check？ PlaintextDecrypt=Plaintext |" + PlaintextDecrypt.Equals(Plaintext));

        }
        private byte[] Combiner(params byte[][] arrays)
        {
            int Length = 0;
            foreach (var arr in arrays) Length += arr.Length;
            byte[] result = new byte[Length];
            int offset = 0;
            foreach (var arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }
            return result;
        }

        public void exmple_RSAOAEP_A128CBC_HS256()
        {
            //Example JWE using RSAES-OAEP and AES GCM
            Console.WriteLine("exmple_RSAOAEP_A128CBC_HS256");

            string plaintext = "The true sign of intelligence is not knowledge but imagination.";
            string headerJson = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
            byte[] cek = new byte[] {
            177,161,244,128,84,143,225,115,63,180,3,255,107,154,212,246,
            138,7,110,91,112,46,34,105,47,130,203,46,122,234,64,252
        };
            byte[] iv = new byte[] { 227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219 };

            // 1. Base64URL encode header
            string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));

            // 2. AAD
            byte[] aad = Encoding.UTF8.GetBytes(encodedHeader);

            // 3. AES-GCM encryption
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            GcmBlockCipher gcm = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(cek), 128, iv, aad);
            gcm.Init(true, parameters);


            // 預留 tag 的空間（plaintext 長度 + 16 bytes）
            byte[] output = new byte[plaintextBytes.Length + 16];
            int outLen = gcm.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, output, 0);
            gcm.DoFinal(output, outLen);


            // 切出 ciphertext 與 tag
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16];

            Array.Copy(output, 0, ciphertext, 0, plaintextBytes.Length);
            Array.Copy(output, plaintextBytes.Length, tag, 0, 16);

            // 4. Encrypt CEK with RSA-OAEP using public key 
            AsymmetricKeyParameter publicKey;

            //            string rsaPublicKeyPem = @"-----BEGIN PUBLIC KEY-----
            //MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA90fF34qtPBKyaquH66Qv
            //b8yMOY5ALmzmT2CuDgFem5uy8sxZz+oan0RIQYNTQxv6F6Vr16UE3ReWEADf0sUT
            //l36EdkvpM0ro3CMsOdTh87QAIH67yd/F5pOXpD7IFO0lphGg1tstHyR3LmGeNok0
            //ZaNrza4JRlRFA3VcBY1dM5dHwiM9kk7Gk8MwxFuEhJnebtdezTTvH3VUV8FLu6ho
            //Ncl45sd9ihQmRNlsGJCtxnUD9LpgJefOG0QLZfG61TMddNEUqtc5iImXdD0TeGDl
            //ZxdJKVqC6N8MYMhdc1JsDXPK7/FQQS2UKAAv0RRkT+1xhOu/RVRqptIU081GTZWg
            //YQIDAQAB
            //-----END PUBLIC KEY-----";
            //using (var reader = new StringReader(rsaPublicKeyPem))
            //{
            //    var pemReader = new PemReader(reader);
            //    publicKey = (AsymmetricKeyParameter)pemReader.ReadObject();
            //} 
            //改為檔案讀取
            string publicKeyPath = Path.Combine("key", "public.pem");
            using (var reader = File.OpenText(publicKeyPath))
            {
                var pemReader = new PemReader(reader);
                publicKey = (AsymmetricKeyParameter)pemReader.ReadObject();
            }
            // 如需轉成 RsaKeyParameters：
            RsaKeyParameters rsaKey = (RsaKeyParameters)publicKey;



            //AsymmetricCipherKeyPair keyPair;
            //using (var reader = new StringReader(rsaPrivateKeyPem))
            //{
            //    var pemReader = new PemReader(reader);
            //    keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            //}

            //var rsaPublic = ((RsaKeyParameters)keyPair.Public);

            //這邊為 導出 PEM ======
            //using (var sw = new StringWriter())
            //{
            //    var pemWriter = new PemWriter(sw);
            //    pemWriter.WriteObject(rsaPublic);
            //    pemWriter.Writer.Flush();

            //    string publicKeyPem = sw.ToString();
            //    Console.WriteLine("publicKeyPem" + publicKeyPem);
            //} 
            //這邊為 導出 PEM ======

            var encryptEngine = new OaepEncoding(new RsaEngine(), new Sha1Digest());
            //encryptEngine.Init(true, rsaPublic);
            encryptEngine.Init(true, rsaKey);
            byte[] encryptedCek = encryptEngine.ProcessBlock(cek, 0, cek.Length);

            // 5. Compact JWE parts
            string part1 = encodedHeader;
            string part2 = Base64UrlEncode(encryptedCek);
            string part3 = Base64UrlEncode(iv);
            string part4 = Base64UrlEncode(ciphertext);
            string part5 = Base64UrlEncode(tag);

            string jwe = $"{part1}.{part2}.{part3}.{part4}.{part5}";
            Console.WriteLine("Compact JWE:\n" + jwe);

            // === Decrypt ===
            // === 解密階段 ===
            //            string rsaPrivatePem = @"-----BEGIN RSA PRIVATE KEY-----
            //MIIEpAIBAAKCAQEA90fF34qtPBKyaquH66Qvb8yMOY5ALmzmT2CuDgFem5uy8sxZ
            //z+oan0RIQYNTQxv6F6Vr16UE3ReWEADf0sUTl36EdkvpM0ro3CMsOdTh87QAIH67
            //yd/F5pOXpD7IFO0lphGg1tstHyR3LmGeNok0ZaNrza4JRlRFA3VcBY1dM5dHwiM9
            //kk7Gk8MwxFuEhJnebtdezTTvH3VUV8FLu6hoNcl45sd9ihQmRNlsGJCtxnUD9Lpg
            //JefOG0QLZfG61TMddNEUqtc5iImXdD0TeGDlZxdJKVqC6N8MYMhdc1JsDXPK7/FQ
            //QS2UKAAv0RRkT+1xhOu/RVRqptIU081GTZWgYQIDAQABAoIBAAHyiaFFrjDUjF1o
            //8ap2Se3ZWGrdHw4Gi0dJgYFoexpiXuXI3HW12CUUNHX4nuuewSjVw4xIl0nW9VZ1
            //rU2TggCdzVUBqsndv4j5SXBAqBFjY+NdoCS6O4yh8a4oVOrORc9BoQjEI940izA9
            //MlHnYXdh8rfFVLseL4d0EYgVKYxeEwr0d3qI+1F5qLreVDGAmreEgh4KhHgnv88f
            //c/TyYNeU9si0Hwu+0yqYImKEpkSglIfghnRcZqEYkTWlibccMTnrpx9AV4RwZbsO
            //BK6rXaSNv1dGu5obgJLnAEtTsiIIyWC3k2NRV+FriS9sMrux/ee+5bbt2hEgx8wD
            //XBrOQxkCgYEA+05BnHRbQCdq/KTj5RTHOTHzSEoRH/IuBA8hXdiMzSQ07L+8cyUu
            //HggTsiTpdySzGiyKvBHn2ukm3EVcVotpahYw3wqe7IRbVvu1D1sgWXvT5AADKABL
            //Idp8XWpFnSd/5jeI8wqdAvzHYDYS0V4gJquHG0zn2IuBuKIZLsHqU0kCgYEA++ZE
            //fba9eK4zRgcCiQOrmbUPa9zJp8hrWoPkJvoxGcFiw/5q9KLW0uUj+juOhOzacvLA
            //rn0Zr15orFL9vrxJYPoe+rX//sGiayahEhhkafuP1P+j7JCcAqDLv2RhtO4NezGU
            //ZPQ7xqsrnVf6vRiArAKY7TeR1cJbXxYo16o9TFkCgYEA4VaJdI3NKNhvkX0VMFuS
            //TFHi0MZBVsDkzBT5GVpM3sGBh2xhwWnsUVdyucFpasEIrAaWnA7+NIftpYO4SY4W
            //ht7BEa5HVNNVx8hJ0Swn9LUZCY+NRPgGZqOv8l+Rblp1z+uqLCwvH/ejmzzBYOUi
            //tSoHKs6p8b0eI32OUSPmRqkCgYAGGJJ7wFphe0W+YhkLm80hUSJoZ9VxfAYtEJgK
            //4W8iwm1TdOq9tNsiC22NdreCPAElWv6SunBOsCg0U2XUodXcxPDO/GyPi7wUf8DS
            //IUj8z5uxeeZLqUw9PAryPMmoiUJGQvLmZoqzyhyqGCD3RoqGnyF4TCn5VFTFvlGK
            //tpH5MQKBgQC2Wq359pwPN+aanBSBGns0SIL5GJZ8bAkBi/DHqSqWx6aMiOgo+sD2
            //nVchW3k0bnZqB7Mpm1XXQAx7j2gJG/vGguSvcopyAOerawtJulgZW7kZOZ+sK+QQ
            //jnR0CxHPrlFcRJiE1L40adTxpzsvwSYqXbRnCPqM86u0HU2bEY1YXg==
            //-----END RSA PRIVATE KEY-----";

            // 解密 encryptedCek
            AsymmetricCipherKeyPair keyPair;
            //using (var reader = new System.IO.StringReader(rsaPrivatePem))
            //{
            //    var pemReader = new PemReader(reader);
            //    keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            //}
            string privateKeyPath = Path.Combine("key", "private.pem");
            using (var reader = File.OpenText(privateKeyPath))
            {
                var pemReader = new PemReader(reader);
                keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            }

            var decryptEngine = new OaepEncoding(new RsaEngine());
            decryptEngine.Init(false, keyPair.Private);
            byte[] decryptedCek = decryptEngine.ProcessBlock(encryptedCek, 0, encryptedCek.Length);

            // 解密 AES-GCM ciphertext
            GcmBlockCipher gcmDec = new GcmBlockCipher(new AesEngine());
            AeadParameters decParams = new AeadParameters(new KeyParameter(decryptedCek), 128, iv, aad);
            gcmDec.Init(false, decParams);

            byte[] cipherPlusTag = new byte[ciphertext.Length + tag.Length];
            Array.Copy(ciphertext, 0, cipherPlusTag, 0, ciphertext.Length);
            Array.Copy(tag, 0, cipherPlusTag, ciphertext.Length, tag.Length);

            byte[] decrypted = new byte[ciphertext.Length];
            int len2 = gcmDec.ProcessBytes(cipherPlusTag, 0, cipherPlusTag.Length, decrypted, 0);
            gcmDec.DoFinal(decrypted, len2);

            Console.WriteLine("\n[Decrypted Plaintext]");
            Console.WriteLine(Encoding.UTF8.GetString(decrypted));

        } 
        public void exmple_RSAOAEP256_A128CBC_HS256()
        {
            //Example JWE using RSAES-OAEP and AES GCM
            Console.WriteLine("exmple_RSAOAEP256_A128CBC_HS256");
            // 1. RFC 範例 Header
            string plaintext = "The true sign of intelligence is not knowledge but imagination.";
            string headerJson = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}";
            byte[] cek = new byte[] {
                177,161,244,128,84,143,225,115,63,180,3,255,107,154,212,246,
                138,7,110,91,112,46,34,105,47,130,203,46,122,234,64,252
            };
            byte[] iv = new byte[] { 227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219 };

            // 1. Base64URL encode header
            string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));

            // 2. AAD
            byte[] aad = Encoding.UTF8.GetBytes(encodedHeader);

            // 3. AES-GCM encryption
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            GcmBlockCipher gcm = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(cek), 128, iv, aad);
            gcm.Init(true, parameters);


            // 預留 tag 的空間（plaintext 長度 + 16 bytes）
            byte[] output = new byte[plaintextBytes.Length + 16];
            int outLen = gcm.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, output, 0);
            gcm.DoFinal(output, outLen);


            // 切出 ciphertext 與 tag
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16];

            Array.Copy(output, 0, ciphertext, 0, plaintextBytes.Length);
            Array.Copy(output, plaintextBytes.Length, tag, 0, 16);

            // 4. Encrypt CEK with RSA-OAEP using public key 
            AsymmetricKeyParameter publicKey;
             
            //改為檔案讀取
            string publicKeyPath = Path.Combine("key", "public.pem");
            using (var reader = File.OpenText(publicKeyPath))
            {
                var pemReader = new PemReader(reader);
                publicKey = (AsymmetricKeyParameter)pemReader.ReadObject();
            }
            // 如需轉成 RsaKeyParameters：
            RsaKeyParameters rsaKey = (RsaKeyParameters)publicKey;
            // RSAOAEP RSAOAEP256 Diff Add new Sha256Digest()
            var encryptEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest());
            //encryptEngine.Init(true, rsaPublic);
            encryptEngine.Init(true, rsaKey);
            byte[] encryptedCek = encryptEngine.ProcessBlock(cek, 0, cek.Length);

            // 5. Compact JWE parts
            string part1 = encodedHeader;
            string part2 = Base64UrlEncode(encryptedCek);
            string part3 = Base64UrlEncode(iv);
            string part4 = Base64UrlEncode(ciphertext);
            string part5 = Base64UrlEncode(tag);

            string jwe = $"{part1}.{part2}.{part3}.{part4}.{part5}";
            Console.WriteLine("Compact JWE:\n" + jwe);

            // === Decrypt ===
            // === 解密階段 ===
            
            // 解密 encryptedCek
            AsymmetricCipherKeyPair keyPair; 
            string privateKeyPath = Path.Combine("key", "private.pem");
            using (var reader = File.OpenText(privateKeyPath))
            {
                var pemReader = new PemReader(reader);
                keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            } 
            // RSAOAEP RSAOAEP256 Diff Add new Sha256Digest()
            var decryptEngine = new OaepEncoding(new RsaEngine(),new Sha256Digest());
            decryptEngine.Init(false, keyPair.Private);
            byte[] decryptedCek = decryptEngine.ProcessBlock(encryptedCek, 0, encryptedCek.Length);

            // 解密 AES-GCM ciphertext
            GcmBlockCipher gcmDec = new GcmBlockCipher(new AesEngine());
            AeadParameters decParams = new AeadParameters(new KeyParameter(decryptedCek), 128, iv, aad);
            gcmDec.Init(false, decParams);

            byte[] cipherPlusTag = new byte[ciphertext.Length + tag.Length];
            Array.Copy(ciphertext, 0, cipherPlusTag, 0, ciphertext.Length);
            Array.Copy(tag, 0, cipherPlusTag, ciphertext.Length, tag.Length);

            byte[] decrypted = new byte[ciphertext.Length];
            int len2 = gcmDec.ProcessBytes(cipherPlusTag, 0, cipherPlusTag.Length, decrypted, 0);
            gcmDec.DoFinal(decrypted, len2);

            Console.WriteLine("\n[Decrypted Plaintext]");
            Console.WriteLine(Encoding.UTF8.GetString(decrypted)); 
        }
    }
}
