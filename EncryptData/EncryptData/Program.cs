using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using EncryptData.Encrypt;

namespace EncryptData
{
    class Program
    {
        static void Main(string[] args)
        {
            string plainText = "foobar";

            var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(2048);

            var publicKeyString = RSAService.getKeyString(rsa.ExportParameters(false));
            var privateKeyString = RSAService.getKeyString(rsa.ExportParameters(true));

            // Encrypt.
            string cypherText = RSAService.Encrypt(plainText, publicKeyString);

            // Decrypt.
            string decryptedText = RSAService.Decrypt(cypherText, privateKeyString);

            Console.WriteLine("Plain Text: " + plainText);
            Console.WriteLine("Cypher Text: " + cypherText);
            Console.WriteLine("Decrypted Text: " + decryptedText);
        }
    }
}
