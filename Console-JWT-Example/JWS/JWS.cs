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
            string JWS = $"{signingInput}.{encodedSignature}";
            Console.WriteLine("JWS:");
            Console.WriteLine(JWS);
            string expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

            Console.WriteLine("Check？JWS=expected |" + (JWS == expected));




        }
    }
}
