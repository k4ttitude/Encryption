using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace EncryptData.Encrypt
{
    class RSAService
    {
        //public static string getKeyString(RSAParameters key)
        //{
        //    var stringWriter = new System.IO.StringWriter();
        //    var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //    xmlSerializer.Serialize(stringWriter, key);
        //    return stringWriter.ToString();
        //}
        
        public static string toJsonParameters(RSAParameters parameters)
        {
            var parasJson = new RSAParametersJson()
            {
                Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                P = parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                Q = parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                DP = parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                DQ = parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                InverseQ = parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                D = parameters.D != null ? Convert.ToBase64String(parameters.D) : null
            };

            return JsonConvert.SerializeObject(parasJson);
        }

        public static RSAParameters fromJsonParameters(string jsonString)
        {
            try
            {
                var paramsJson = JsonConvert.DeserializeObject<RSAParametersJson>(jsonString);

                RSAParameters parameters = new RSAParameters();

                parameters.Modulus = paramsJson.Modulus != null ? Convert.FromBase64String(paramsJson.Modulus) : null;
                parameters.Exponent = paramsJson.Exponent != null ? Convert.FromBase64String(paramsJson.Exponent) : null;
                parameters.P = paramsJson.P != null ? Convert.FromBase64String(paramsJson.P) : null;
                parameters.Q = paramsJson.Q != null ? Convert.FromBase64String(paramsJson.Q) : null;
                parameters.DP = paramsJson.DP != null ? Convert.FromBase64String(paramsJson.DP) : null;
                parameters.DQ = paramsJson.DQ != null ? Convert.FromBase64String(paramsJson.DQ) : null;
                parameters.InverseQ = paramsJson.InverseQ != null ? Convert.FromBase64String(paramsJson.InverseQ) : null;
                parameters.D = paramsJson.D != null ? Convert.FromBase64String(paramsJson.D) : null;

                return parameters;
            }
            catch
            {
                throw new Exception("Invalid JSON RSA key.");
            }
        }

        public static string Encrypt(string plainText, string publicKeyString)
        {
            var bytesPlainText = Encoding.UTF8.GetBytes(plainText);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    //rsa.FromXmlString(publicKeyString);
                    var parameters = fromJsonParameters(publicKeyString);
                    rsa.ImportParameters(parameters);

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

        public static string Decrypt(string encryptedText, string privateKeyString)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    //rsa.FromXmlString(privateKey);
                    var parameters = fromJsonParameters(privateKeyString);
                    rsa.ImportParameters(parameters);

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
