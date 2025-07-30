using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Console_JWT_Example
{
    internal class Base
    {
        // Base64Url 編碼（去掉 =、替換 URL 安全字元）
        protected string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").Replace("=", ""); ;
        }
        protected string Base64UrlEncode(string input)
        {
            byte[] InputBytes = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(InputBytes).Replace("+", "-").Replace("/", "_").Replace("=", ""); ;
        }
        // Base64Url 解碼（補上 =、還原 URL 安全字元）
        protected byte[] Base64UrlDecode(string input)
        {
            string Padded = input.Replace('-', '+').Replace('_', '/');
            switch (Padded.Length % 4)
            {
                case 2: Padded += "=="; break;
                case 3: Padded += "="; break;
                case 1: Padded += "==="; break;
            }
            return Convert.FromBase64String(Padded);
        }
        protected string Base64UrlDecodeToString(string input)
        {
            string Padded = input.Replace('-', '+').Replace('_', '/');
            switch (Padded.Length % 4)
            {
                case 2: Padded += "=="; break;
                case 3: Padded += "="; break;
                case 1: Padded += "==="; break;
            }
            return Encoding.UTF8.GetString(Convert.FromBase64String(Padded));
        }
        protected byte[] StringToBytes(string input)
        {
            return Encoding.UTF8.GetBytes(input);
        }
        protected string BytesToString(byte[] input)
        {
            return Encoding.UTF8.GetString(input);
        }
        protected string BytesToHexString(byte[] bytes)
        {
            return Convert.ToHexString(bytes);
        }
        public  byte[] HexStringToBytes(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        protected byte[] XorBytes(byte[] array1, byte[] array2)
        {
            if (array1 == null || array2 == null)
                throw new ArgumentNullException("輸入陣列不能為 null。");
            if (array1.Length != array2.Length)
                throw new ArgumentException("兩個陣列的長度必須相同才能執行 XOR 運算。");
            byte[] result = new byte[array1.Length];
            for (int i = 0; i < array1.Length; i++)
            {
                result[i] = (byte)(array1[i] ^ array2[i]);
            }
            return result;
        }
    }
}
