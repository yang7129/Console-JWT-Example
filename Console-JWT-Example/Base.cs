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
            return Convert.ToBase64String(input).Replace('+', '-').Replace('/', '_').Replace("=", "");
        }
        protected string Base64UrlEncode(string input)
        {
            byte[] InputBytes = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(InputBytes).Replace('+', '-').Replace('/', '_').Replace("=", "");
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
    }
}
