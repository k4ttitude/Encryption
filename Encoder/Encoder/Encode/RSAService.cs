using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Encoder.Encode
{
    class RSAService
    {
        public static string getKeyString(RSAParameters key)
        {
            var sw = new System.IO.StringWriter();
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, key);
            return sw.ToString();
        }

        public static string Encrypt(string plainText, string publicKeyString)
        {
            var bytesPlainText = Encoding.UTF8.GetBytes(plainText);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(publicKeyString.ToString());

                    var bytesCypherText = rsa.Encrypt(bytesPlainText, true);
                    var cypherText = Convert.ToBase64String(bytesCypherText);

                    return cypherText;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
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
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}
