using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public  class AesOperation
    {
        public static string EncryptString(string key, string plainText)
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public static string DecryptString(string key, string cipherText)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}


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