using CryptoLibrary;
using System.Runtime.Intrinsics.X86;
using System.Text;

internal class CryptoApp
{
    private static void Main(string[] args)
    {
        Console.WriteLine("Crypto Application Running..");
        var cryptoLibrary = new CryptoLibrary.Crypto();
        string sourceFilePath = "input.txt";
        string sourceText = File.ReadAllText(sourceFilePath);
        
        byte[] data = Encoding.UTF8.GetBytes(sourceText);

      
        // SHA-1
        byte[] sha1Hash = Crypto.ComputeSHA1(data);
        Console.WriteLine("SHA-1: " + cryptoLibrary.ByteArrayToHex(sha1Hash) + "\n");

        // SHA-256
        byte[] sha256Hash = Crypto.ComputeSHA256(data);
        Console.WriteLine("SHA-256: " + cryptoLibrary.ByteArrayToHex(sha256Hash)+"\n");

        // SHA-512
        byte[] sha512Hash = Crypto.ComputeSHA512(data);
        Console.WriteLine("SHA-512: " + cryptoLibrary.ByteArrayToHex(sha512Hash) + "\n");

        // DES
        string desKey = "00196761"; // 8 characters for DES
        byte[] desEncryptedData = cryptoLibrary.DESEncrypt(data, desKey);
        byte[] desDecryptedData = cryptoLibrary.DESDecrypt(desEncryptedData, desKey);
        Console.WriteLine("DES Encrypted: " + Encoding.UTF8.GetString(desEncryptedData)+ "\n");
        Console.WriteLine("DES Decrypted: " + Encoding.UTF8.GetString(desDecryptedData) + "\n");

        // AES
        string aesKey = "Trabzonspor01967"; // 16 characters for AES-128, 24 characters for AES-192, 32 characters for AES-256
        byte[] aesEncryptedData = cryptoLibrary.AESEncrypt(data, aesKey);
        byte[] aesDecryptedData = cryptoLibrary.AESDecrypt(aesEncryptedData, aesKey);
        Console.WriteLine("AES Encrypted: " + Encoding.UTF8.GetString(aesEncryptedData)+ "\n");
        Console.WriteLine("AES Decrypted: " + Encoding.UTF8.GetString(aesDecryptedData) + "\n");

        // HMAC-SHA1
        byte[] hmacSha1Key = Encoding.UTF8.GetBytes("Trabzonspor");
        byte[] hmacSha1Hash = cryptoLibrary.ComputeHMACSHA1(data, hmacSha1Key);
        Console.WriteLine("HMAC-SHA1: " + cryptoLibrary.ByteArrayToHex(hmacSha1Hash) + "\n");

        // HMAC-SHA256
        byte[] hmacSha256Key = Encoding.UTF8.GetBytes("myhmac256key");
        byte[] hmacSha256Hash = cryptoLibrary.ComputeHMACSHA256(data, hmacSha256Key);
        Console.WriteLine("HMAC-SHA256: " + cryptoLibrary.ByteArrayToHex(hmacSha256Hash) + "\n");

        // CRC32
        byte[] crc32Hash = cryptoLibrary.ComputeCRC32(data);
        Console.WriteLine("CRC32: " + cryptoLibrary.ByteArrayToHex(crc32Hash) + "\n");

        // MD5
        byte[] md5Hash = cryptoLibrary.ComputeMD5(data);
        Console.WriteLine("MD5: " + cryptoLibrary.ByteArrayToHex(md5Hash) + "\n");

        // CBC
        string aesKey1 = "aeskey1234567890"; // 16 characters for AES-128, 24 characters for AES-192, 32 characters for AES-256
        byte[] encryptedBytes = Crypto.EncryptCBC(data, aesKey1);
        string decryptedText  = Crypto.DecryptCBC(encryptedBytes, aesKey1);
        Console.WriteLine("CBC Encrypted Text: " + Convert.ToBase64String(encryptedBytes) + "\n");
        Console.WriteLine("CBC Decrypted Text: " + decryptedText + "\n");


        //HOTP
        string key = "Trabzonspor";
        long counter = 123456;
        string otp = Crypto.GenerateHOTP(key, counter);
        Console.WriteLine("Generated OTP: " + otp);


        Console.ReadLine();
    }
}