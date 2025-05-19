// See https://aka.ms/new-console-template for more information
using Console_JWT_Example.JWT;
// Install Nuget Portable.BouncyCastle-V1.9.0
Console.WriteLine("Start=============");
// reference
// https://jwt.io/
// https://www.bejson.com/jwt/
#region JWT
JWT JWT = new JWT();
JWT.exmple_HS256();
#endregion

Console.WriteLine("End=============");

//public void exmple_()
//{
//    Console.WriteLine("exmple_");
//}