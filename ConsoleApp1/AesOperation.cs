using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    public class AesOperation
    {
        public static string GenerateKey()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateKey();
                return Convert.ToBase64String(aes.Key);
            }
        }

        public static string EncryptString(string key, string plainText)
        {
            byte[] iv = new byte[16];
            byte[] array;

            // Embed DateTime
            string timestamp = DateTime.Now.ToString("o"); // ISO 8601 format
            string enrichedText = $"{timestamp}|{plainText}";

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(PadKey(key));
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(enrichedText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public static string DecryptString(string key, string cipherText, out DateTime timestamp)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(PadKey(key));
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            string decryptedText = streamReader.ReadToEnd();

                            // Extract timestamp and actual message
                            var parts = decryptedText.Split('|');
                            if (parts.Length >= 2 && DateTime.TryParse(parts[0], null, System.Globalization.DateTimeStyles.RoundtripKind, out timestamp))
                            {
                                return parts[1];
                            }
                            else
                            {
                                timestamp = DateTime.MinValue;
                                return decryptedText; // Return full string in case of error
                            }
                        }
                    }
                }
            }
        }

        private static string PadKey(string key)
        {
            const int keySize = 32; // AES-256
            if (key.Length > keySize)
                return key.Substring(0, keySize);
            return key.PadRight(keySize, '0');
        }
    }
}


//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Security.Cryptography;
//using System.Text;
//using System.Threading.Tasks;

//namespace ConsoleApp1
//{
//    public  class AesOperation
//    {
//        public static string EncryptString(string key, string plainText)
//        {
//            byte[] iv = new byte[16];
//            byte[] array;

//            using (Aes aes = Aes.Create())
//            {
//                aes.Key = Encoding.UTF8.GetBytes(key);
//                aes.IV = iv;

//                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

//                using (MemoryStream memoryStream = new MemoryStream())
//                {
//                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
//                    {
//                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
//                        {
//                            streamWriter.Write(plainText);
//                        }

//                        array = memoryStream.ToArray();
//                    }
//                }
//            }

//            return Convert.ToBase64String(array);
//        }

//        public static string DecryptString(string key, string cipherText)
//        {
//            byte[] iv = new byte[16];
//            byte[] buffer = Convert.FromBase64String(cipherText);

//            using (Aes aes = Aes.Create())
//            {
//                aes.Key = Encoding.UTF8.GetBytes(key);
//                aes.IV = iv;
//                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

//                using (MemoryStream memoryStream = new MemoryStream(buffer))
//                {
//                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
//                    {
//                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
//                        {
//                            return streamReader.ReadToEnd();
//                        }
//                    }
//                }
//            }
//        }
//    }
//}


/*
 pyhton key
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_string(key, plaintext):
    iv = b'\x00' * 16
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_string(key, ciphertext):
    iv = b'\x00' * 16
    ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    return plaintext.decode('utf-8')

key = "b14ca5898a4e4133bbce2ea2315a1916"

plain_text = "APPLE_BALL"
cipher_text = encrypt_string(key,plain_text)
decrypted_string = decrypt_string(key,cipher_text)

print(cipher_text)
print(decrypted_string)

 */