// See https://aka.ms/new-console-template for more information
using Console_JWT_Example.JWT;
using Console_JWT_Example.JWS;
using Console_JWT_Example.JWE;
// Install Nuget Portable.BouncyCastle-V1.9.0
Console.WriteLine("Start=============");
// reference
// https://jwt.io/
// https://www.bejson.com/jwt/
//#region JWT
//JWT JWT = new JWT();
//JWT.exmple_HS256();
//#endregion
//#region JWS
//JWS JWS = new JWS();
//JWS.exmple_HMACSHA_256();
//#endregion
#region JWE
JWE JWE = new JWE();
//JWE.exmple_AESKW_AES_128_CBC_HMAC_SHA_256();
//JWE.exmple_RSAOAEP_A256GCM();
JWE.exmple_RSAOAEP256_A256GCM();
#endregion

Console.WriteLine("End=============");

//public void exmple_()
//{
//    Console.WriteLine("exmple_");
//}