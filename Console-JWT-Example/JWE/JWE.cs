using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Console_JWT_Example.JWE
{
    internal class JWE : Base
    {
        public void exmple_AESKWandAES128CBCHMACSHA256()
        {
            //Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
            Console.WriteLine("exmple_AESKWandAES128CBCHMACSHA256");
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
    }
}
