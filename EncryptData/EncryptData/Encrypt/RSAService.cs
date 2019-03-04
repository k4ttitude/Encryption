using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace EncryptData.Encrypt
{
    class RSAService
    {
        public static string getKeyString(RSAParameters key)
        {
            var stringWriter = new System.IO.StringWriter();
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xmlSerializer.Serialize(stringWriter, key);
            return stringWriter.ToString();
        }

        public static string Encrypt(string plainText, string publicKeyString)
        {
            var bytesPlainText = Encoding.UTF8.GetBytes(plainText);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(publicKeyString);

                    var bytesCypherText = rsa.Encrypt(bytesPlainText, true);
                    var cypherText = Convert.ToBase64String(bytesCypherText);

                    return cypherText;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.StackTrace);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
                return null;
            }
        }

        public static string Decrypt(string encryptedText, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(privateKey);

                    var bytesCypherText = Convert.FromBase64String(encryptedText);

                    var bytesPlainText = rsa.Decrypt(bytesCypherText, true);
                    var plainText = Encoding.UTF8.GetString(bytesPlainText);

                    return plainText.ToString();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.StackTrace);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
                return null;
            }
        }
    }
}
