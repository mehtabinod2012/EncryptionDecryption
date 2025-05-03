

//// See https://aka.ms/new-console-template for more information




using ConsoleApp1;

class Program
{
    static void Main(string[] args)
    {
        string key = AesOperation.GenerateKey(); // You can store this safely for reuse

        Console.WriteLine($"Generated Key: {key}");
        Console.WriteLine("Please enter a string for encryption:");
        var str = Console.ReadLine();

        var encryptedString = AesOperation.EncryptString(key, str);
        Console.WriteLine($"Encrypted String = {encryptedString}");

        var decryptedString = AesOperation.DecryptString(key, encryptedString, out DateTime encryptionTime);
        Console.WriteLine($"Decrypted String = {decryptedString}");
        Console.WriteLine($"Encrypted At (UTC) = {encryptionTime}");

        Console.ReadKey();
    }
}



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




