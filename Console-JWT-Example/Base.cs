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
        // Base64Url 解碼（補上 =、還原 URL 安全字元）
        protected byte[] Base64UrlDecode(string input)
        {
            string padded = input.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "="; break;
                case 1: padded += "==="; break;
            }
            return Convert.FromBase64String(padded);
        }
        protected string Base64UrlDecodeToString(string input)
        {
            string padded = input.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "="; break;
                case 1: padded += "==="; break;
            }
            return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
        }
    }
}
