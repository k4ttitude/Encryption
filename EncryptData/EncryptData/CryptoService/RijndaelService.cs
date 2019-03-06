using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace EncryptData.CryptoService
{
    class RijndaelService
    {
        /// <summary>
        /// Encrypt Plain Text using Rijndael.
        /// </summary>
        /// <param name="plainText">Plain text</param>
        /// <param name="Key">Key</param>
        /// <param name="IV">Initialization Vector</param>
        /// <returns>Base64 string representation of Cypher Bytes</returns>
        public static string Encrypt(string plainText, string Key, string IV)
        {
            // Check arguments.
           if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] keyBytes = Convert.FromBase64String(Key);
            byte[] ivBytes = Convert.FromBase64String(IV);

            // return value.
            byte[] encrypted;

            // Create an Rijndael object
            // with the specified key and IV.
            using (Rijndael rd = Rijndael.Create())
            {
                rd.Key = keyBytes;
                rd.IV = ivBytes;

                // Create the Encryptor.
                ICryptoTransform encryptor = rd.CreateEncryptor(rd.Key, rd.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptoStream))
                        {
                            writer.Write(plainText);
                        }
                        encrypted = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypt Cypher Text with Rijndael.
        /// </summary>
        /// <param name="cypherBytes">Cypher Bytes Array</param>
        /// <param name="Key">Key</param>
        /// <param name="IV">Initialization Vector</param>
        /// <returns>Plain Text</returns>
        public static string Decrypt(string cypherText, string Key, string IV)
        {
            // Check arguments.
            if (cypherText == null || cypherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // string to bytes arrays.
            byte[] cypherBytes = Convert.FromBase64String(cypherText);
            byte[] keyBytes = Convert.FromBase64String(Key);
            byte[] ivBytes = Convert.FromBase64String(IV);

            // return value.
            string plainText = null;

            // Create an Rijndael object
            // with the specified key and IV.
            using (Rijndael rd = Rijndael.Create())
            {
                rd.Key = keyBytes;
                rd.IV = ivBytes;

                // Create the Decryptor.
                ICryptoTransform decryptor = rd.CreateDecryptor();

                using (MemoryStream memoryStream = new MemoryStream(cypherBytes))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cryptoStream))
                        {
                            plainText = reader.ReadToEnd();
                        }
                    }
                }
            }

            return plainText;
        }
    }
}
