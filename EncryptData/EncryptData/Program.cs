using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using EncryptData.CryptoService;

namespace EncryptData
{
    class Program
    {
        static void Main(string[] args)
        {
            string plainText = "Using encryption with .NET is very easy. For this, we use the RijnDaelManaged class. We need to initialize this class by calling <code>NewRijndaelManaged() after the class is created we have to create our secret key by creating a class called Rfc2898DeriveBytes like this Rfc2898DeriveBytes(Inputkey, salt). The constructor on this class needs 2 input parameters, a password and a salt key. In the code below, we use two GUIDs as the pasword and salt key.";

            string cypherText, decryptedText;

            // Generate new keys.
            var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(2048);

            var publicKeyString = RSAService.toJsonParameters(rsa.ExportParameters(false));
            var privateKeyString = RSAService.toJsonParameters(rsa.ExportParameters(true));

            Console.WriteLine("Plain Text: " + plainText);
            //Console.WriteLine("Cypher Text: " + cypherText);
            //Console.WriteLine("Decrypted Text: " + decryptedText);

            var rd = System.Security.Cryptography.Rijndael.Create();
            var inputKeyString = Convert.ToBase64String(rd.Key);
            var ivString = Convert.ToBase64String(rd.IV);

            Console.WriteLine("Rijndael Input Key: " + inputKeyString);
            Console.WriteLine("Rijndael IV: " + ivString);

            // Encrypt the input key with RSA public key.
            var encryptedInputKey = RSAService.Encrypt(inputKeyString, publicKeyString);
            var encryptedIV = RSAService.Encrypt(ivString, publicKeyString);
            Console.WriteLine("Encrypted Input Key: " + encryptedInputKey);
            Console.WriteLine("Encrypted IV: " + encryptedIV);

            // Encrypt data with Rijndael input key.
            cypherText = RijndaelService.Encrypt(plainText, inputKeyString, ivString);
            Console.WriteLine("Encrypted Data: " + cypherText);

            // Decrypt the input key with RSA private key.
            var decryptedInputKey = RSAService.Decrypt(encryptedInputKey, privateKeyString);
            var decryptedIV = RSAService.Decrypt(encryptedIV, privateKeyString);
            decryptedText = RijndaelService.Decrypt(cypherText, decryptedInputKey, decryptedIV);

            Console.WriteLine("Decrypted Data: " + decryptedText);
        }
    }
}
