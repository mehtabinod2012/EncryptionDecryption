using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq; // Using XDocument for safer XML handling

namespace ConsoleAppRsa
{
    public static class RsaKeyManager
    {
        private const string PublicKeyFileName = "publicKey.xml";
        private const string PrivateKeyFileName = "privateKey.xml";

        /// <summary>
        /// Checks if RSA key files exist.
        /// </summary>
        /// <returns>True if both public and private key files exist, otherwise false.</returns>
        public static bool KeysExist()
        {
            return File.Exists(PublicKeyFileName) && File.Exists(PrivateKeyFileName);
        }

        /// <summary>
        /// Loads the public key from a file.
        /// </summary>
        /// <returns>The public key as an XML string, or null if the file doesn't exist or an error occurs.</returns>
        public static string LoadPublicKey()
        {
            try
            {
                if (File.Exists(PublicKeyFileName))
                {
                    return File.ReadAllText(PublicKeyFileName);
                }
                else
                {
                    Console.WriteLine($"Warning: Public key file '{PublicKeyFileName}' not found.");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading public key: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Loads the private key from a file.
        /// </summary>
        /// <returns>The private key as an XML string, or null if the file doesn't exist or an error occurs.</returns>
        public static string LoadPrivateKey()
        {
            try
            {
                if (File.Exists(PrivateKeyFileName))
                {
                    return File.ReadAllText(PrivateKeyFileName);
                }
                else
                {
                    Console.WriteLine($"Warning: Private key file '{PrivateKeyFileName}' not found.");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading private key: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Saves the public key to a file.
        /// </summary>
        /// <param name="publicKeyXml">The XML string representation of the public key.</param>
        public static void SavePublicKey(string publicKeyXml)
        {
            try
            {
                File.WriteAllText(PublicKeyFileName, publicKeyXml);
                Console.WriteLine($"Public key saved to '{PublicKeyFileName}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving public key: {ex.Message}");
            }
        }

        /// <summary>
        /// Saves the private key to a file.
        /// </summary>
        /// <param name="privateKeyXml">The XML string representation of the private key.</param>
        public static void SavePrivateKey(string privateKeyXml)
        {
            try
            {
                // Consider encrypting the private key for production environments
                File.WriteAllText(PrivateKeyFileName, privateKeyXml);
                Console.WriteLine($"Private key saved to '{PrivateKeyFileName}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving private key: {ex.Message}");
            }
        }
    }

    public class RsaOperation
    {
        /// <summary>
        /// Generates a new RSA key pair and saves them to files.
        /// </summary>
        /// <param name="keySize">The size of the key to generate, in bits. Default is 2048.</param>
        public static void GenerateAndSaveKeys(int keySize = 2048)
        {
            using (RSA rsa = RSA.Create(keySize))
            {
                // Export public key
                string publicKeyXml = rsa.ToXmlString(false);

                // Export private key (which also includes public key parts)
                string privateKeyXml = rsa.ToXmlString(true);

                // Save the keys
                RsaKeyManager.SavePublicKey(publicKeyXml);
                RsaKeyManager.SavePrivateKey(privateKeyXml);
            }
        }

        /// <summary>
        /// Encrypts a string using the RSA public key loaded from a file.
        /// </summary>
        /// <param name="plainText">The string to encrypt.</param>
        /// <returns>The Base64 encoded encrypted string, or null if an error occurs.</returns>
        public static string EncryptString(string plainText)
        {
            string publicKeyXml = RsaKeyManager.LoadPublicKey();
            if (string.IsNullOrEmpty(publicKeyXml))
            {
                return null;
            }

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes;

            using (RSA rsa = RSA.Create())
            {
                try
                {
                    rsa.FromXmlString(publicKeyXml);
                    encryptedBytes = rsa.Encrypt(plainBytes, RSAEncryptionPadding.OaepSHA256);
                    return Convert.ToBase64String(encryptedBytes);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during encryption: {ex.Message}");
                    return null;
                }
            }
        }

        /// <summary>
        /// Decrypts a string using the RSA private key loaded from a file.
        /// </summary>
        /// <param name="cipherText">The Base64 encoded encrypted string.</param>
        /// <returns>The decrypted string, or null if an error occurs.</returns>
        public static string DecryptString(string cipherText)
        {
            string privateKeyXml = RsaKeyManager.LoadPrivateKey();
            if (string.IsNullOrEmpty(privateKeyXml))
            {
                return null;
            }

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] decryptedBytes;

            using (RSA rsa = RSA.Create())
            {
                try
                {
                    rsa.FromXmlString(privateKeyXml);
                    decryptedBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during decryption: {ex.Message}");
                    return null;
                }
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("RSA Key Management Example\n");

            if (!RsaKeyManager.KeysExist())
            {
                Console.WriteLine("No existing RSA keys found. Generating new 2048-bit key pair...");
                RsaOperation.GenerateAndSaveKeys();
                Console.WriteLine("\nKey generation complete.");
            }
            else
            {
                Console.WriteLine("Existing RSA keys found. Using those keys.");
            }

            Console.WriteLine("\nPlease enter a string for encryption:");
            var originalString = Console.ReadLine();

            if (!string.IsNullOrEmpty(originalString))
            {
                // Embed DateTime (similar to your AES example)
                string timestamp = DateTime.UtcNow.ToString("o"); // ISO 8601 format, UTC is good practice
                string stringToEncrypt = $"{timestamp}|{originalString}";
                Console.WriteLine($"String to encrypt (with timestamp): {stringToEncrypt}");

                // Encrypt with Public Key
                Console.WriteLine("\nEncrypting with Public Key...");
                var encryptedString = RsaOperation.EncryptString(stringToEncrypt);

                if (!string.IsNullOrEmpty(encryptedString))
                {
                    Console.WriteLine($"Encrypted String (Base64) = {encryptedString}");
                    Console.WriteLine($"Encryption Processed At (UTC) = {DateTime.UtcNow.ToString("o")}");

                    // Decrypt with Private Key
                    Console.WriteLine("\nDecrypting with Private Key...");
                    string decryptedEnrichedString = RsaOperation.DecryptString(encryptedString);

                    if (!string.IsNullOrEmpty(decryptedEnrichedString))
                    {
                        // Extract timestamp and actual message
                        DateTime encryptionTime = DateTime.MinValue;
                        string decryptedOriginalString = decryptedEnrichedString; // Default if parsing fails

                        var parts = decryptedEnrichedString.Split(new[] { '|' }, 2); // Split only on the first '|'
                        if (parts.Length == 2 && DateTime.TryParse(parts[0], null, System.Globalization.DateTimeStyles.RoundtripKind, out encryptionTime))
                        {
                            decryptedOriginalString = parts[1];
                        }
                        else
                        {
                            Console.WriteLine("Warning: Could not parse timestamp from decrypted string.");
                        }

                        Console.WriteLine($"Decrypted Original String = {decryptedOriginalString}");
                        if (encryptionTime != DateTime.MinValue)
                        {
                            Console.WriteLine($"Message was originally timestamped at (UTC) = {encryptionTime:o}");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Decryption failed.");
                    }
                }
                else
                {
                    Console.WriteLine("Encryption failed.");
                }
            }
            else
            {
                Console.WriteLine("No string entered for encryption.");
            }

            Console.WriteLine("\nPress any key to exit.");
            Console.ReadKey();
        }
    }
}


/* working 1 solution
 * 
 
using ConsoleApp1;

class Program
{
    static void Main(string[] args)
    {
        //string key = "b14ca5898a4e4133bbce2ea2315a1916";//
        string key = AesOperation.GenerateKey(); // You can store this safely for reuse

        Console.WriteLine($"Generated Key: {key}");
        Console.WriteLine("Please enter a string for encryption:");
        var str = Console.ReadLine();


        var encryptedString = AesOperation.EncryptString(key, str);
        Console.WriteLine($"Encrypted String = {encryptedString}");
        Console.WriteLine($"Encrypted Date Time = {DateTime.Now.ToString("o")}");

        var decryptedString = AesOperation.DecryptString(key, encryptedString, out DateTime encryptionTime);
        Console.WriteLine($"Decrypted String = {decryptedString}");
        Console.WriteLine($"Encrypted At (UTC) = {encryptionTime}");

        Console.ReadKey();
    }
}

*/

/* old code

//using ConsoleApp1;

//Console.WriteLine("Hello, World!");

//var key = "b14ca5898a4e4133bbce2ea2315a1916";

//            //Console.WriteLine("Please enter a secret key for the symmetric algorithm.");
//            //var key = Console.ReadLine();

//            Console.WriteLine("Please enter a string for encryption");
//            var str = Console.ReadLine();
//            var encryptedString = AesOperation.EncryptString(key, str);
//            Console.WriteLine($"encrypted string = {encryptedString}");

//            var decryptedString = AesOperation.DecryptString(key, encryptedString);
//            Console.WriteLine($"decrypted string = {decryptedString}");

//            Console.ReadKey();

//Console.ReadLine();

*/


