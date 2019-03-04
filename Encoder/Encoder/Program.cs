using System;
using System.Security.Cryptography;
using System.Text;

using Encoder.Encode;

namespace Encoder
{
    class Program
    {
        static void Main(string[] args)
        {
            string plainText = "foobar";

            var rsa = new RSACryptoServiceProvider(2048);

            var publicKeyString = RSAService.getKeyString(rsa.ExportParameters(false));
            var privateKeyString = RSAService.getKeyString(rsa.ExportParameters(true));

            // Encrypt.
            string cypherText = Encode.RSAService.Encrypt(plainText, publicKeyString);

            // Decrypt.
            string decryptedText = Encode.RSAService.Decrypt(cypherText, privateKeyString);

            Console.WriteLine(decryptedText);
        }
    }
}
