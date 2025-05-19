
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using System.Text.Json;

namespace Console_JWT_Example.JWT
{
    internal class JWT : Base
    {
        public void exmple_HS256()
        {
            Console.WriteLine("exmple_HS256");
            // JWT Token
            // JWT Value = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ind3dy5iZWpzb24uY29tIiwic3ViIjoiZGVtbyIsImlhdCI6MTc0NzYxODA0MywibmJmIjoxNzQ3NjE4MDQzLCJleHAiOjE3NDc3MDQ0NDN9.b_8Zch2tJe2lgEOC0ctRjPOCvyyaG3siLxW2-iYGuoE
            // Header = {"alg": "HS256","typ": "JWT"}
            // Payload ={"username": "www.bejson.com","sub": "demo","iat": 1747618043,"nbf": 1747618043,"exp": 1747704443}
            // HMAC Key = bejson 

            Console.WriteLine("符合 RFC 7519 的 JWT：");

            string headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            //  encodedHeader = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
            string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            // Decode JWT Headjson
            Console.WriteLine(Base64UrlDecodeToString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));


            string payloadJson = "{\"username\":\"www.bejson.com\",\"sub\":\"demo\",\"iat\":1747618043,\"nbf\":1747618043,\"exp\":1747704443}";
            // encodedPayload = eyJ1c2VybmFtZSI6Ind3dy5iZWpzb24uY29tIiwic3ViIjoiZGVtbyIsImlhdCI6MTc0NzYxODA0MywibmJmIjoxNzQ3NjE4MDQzLCJleHAiOjE3NDc3MDQ0NDN9
            string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            // Decode JWT payloadJson
            Console.WriteLine(Base64UrlDecodeToString("eyJ1c2VybmFtZSI6Ind3dy5iZWpzb24uY29tIiwic3ViIjoiZGVtbyIsImlhdCI6MTc0NzYxODA0MywibmJmIjoxNzQ3NjE4MDQzLCJleHAiOjE3NDc3MDQ0NDN9"));


            // encodedHeader.encodedPayload
            string signingInput = $"{encodedHeader}.{encodedPayload}";

            string key = "bejson";
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            byte[] signatureBytes;
            using (var hmac = new HMACSHA256(keyBytes))
            {
                signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput));
            }
            string encodedSignature = Base64UrlEncode(signatureBytes);
            // encodedHeader.encodedPayload.encodedSignature
            string jwt = $"{signingInput}.{encodedSignature}";
            Console.WriteLine("JWT:");
            Console.WriteLine(jwt);
            string expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ind3dy5iZWpzb24uY29tIiwic3ViIjoiZGVtbyIsImlhdCI6MTc0NzYxODA0MywibmJmIjoxNzQ3NjE4MDQzLCJleHAiOjE3NDc3MDQ0NDN9.b_8Zch2tJe2lgEOC0ctRjPOCvyyaG3siLxW2-iYGuoE";

            Console.WriteLine("Check？jwt=expected |" + (jwt == expected));
        }
    }
}
