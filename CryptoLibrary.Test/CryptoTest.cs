using System;
using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using static System.Net.WebRequestMethods;
using File = System.IO.File;

namespace CryptoLibrary.Test
{
    public class CryptoTest
    {
        private readonly Crypto crypto;

        public CryptoTest()
        {
            crypto = new Crypto();
        }

        [Fact]
        public void ComputeSHA1_ValidData_ComputesCorrectHash()
        {
            
            string filePath = File.ReadAllText("TransformFile/input.txt");
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes(filePath); 

            // Act
            byte[] hash = Crypto.ComputeSHA1(data);

            // Assert
            string expectedHash = "55 BC A9 71 6F C0 CD CE 03 C8 D1 2B 35 FA 30 78 3A 77 65 38";
            
            expectedHash = expectedHash.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHash, Crypto.ByteArrayToHex(hash));
        }

        [Fact]
        public void ComputeSHA256_ValidData_ComputesCorrectHash()
        {
            // Arrange
            string filePath = File.ReadAllText("TransformFile/input.txt");

            byte[] data = Encoding.UTF8.GetBytes(filePath); 

            // Act
            byte[] hash = Crypto.ComputeSHA256(data);

            // Assert
            string expectedHash = "59 D1 6C 31 32 AE 41 C0 F5 19 8F 77 C6 A1 59 C4 03 51 D2 88 52 C0 37 BF 0B 24 11 BE 7B DB 57 36";
            expectedHash = expectedHash.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHash, Crypto.ByteArrayToHex(hash));
        }

        [Fact]
        public void DESEncryptAndDecrypt_ValidData_EncryptsAndDecryptsCorrectly()
        {
            // Arrange
            string filePath = File.ReadAllText("TransformFile/input.txt");
            byte[] data = Encoding.UTF8.GetBytes(filePath); 
            string key = "00196761"; 

            // Act
            byte[] encrypted = crypto.DESEncrypt(data, key);
            byte[] decrypted = crypto.DESDecrypt(encrypted, key);

            // Assert
            string decryptedText = Encoding.UTF8.GetString(decrypted);
            Assert.Equal(filePath, decryptedText);
        }

        [Fact]
        public void AESEncryptAndDecrypt_ValidData_EncryptsAndDecryptsCorrectly()
        {
            // Arrange
            string filePath = File.ReadAllText("TransformFile/input.txt");
            byte[] data = Encoding.UTF8.GetBytes(filePath); 
            string key = "Trabzonspor01967"; 

            // Act
            byte[] encrypted = crypto.AESEncrypt(data, key);
            byte[] decrypted = crypto.AESDecrypt(encrypted, key);

            // Assert
            string decryptedText = Encoding.UTF8.GetString(decrypted);
            Assert.Equal(filePath, decryptedText);
        }

        [Fact]
        public void ComputeHMACSHA1_ValidData_ComputesCorrectHMAC()
        {
            // Arrange
            string filePath = File.ReadAllText("TransformFile/input.txt");
            byte[] data = Encoding.UTF8.GetBytes(filePath); 
            byte[] key = Encoding.UTF8.GetBytes("Trabzonspor");

            // Act
            byte[] hmac = crypto.ComputeHMACSHA1(data, key);

            // Assert
            string expectedHmac = "DA 44 2D BC 79 83 10 B8 EC 2F ED D8 8E 45 D6 25 2D FD BC EE";
            expectedHmac = expectedHmac.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHmac, Crypto.ByteArrayToHex(hmac));
        }

        [Fact]
        public void ComputeHMACSHA256_ValidData_ComputesCorrectHMAC()
        {
            // Arrange
            string filePath = File.ReadAllText("TransformFile/input.txt");
            byte[] data = Encoding.UTF8.GetBytes(filePath);
            byte[] key = Encoding.UTF8.GetBytes("trbznsha256"); 

            // Act
            byte[] hmac = crypto.ComputeHMACSHA256(data, key);

            // Assert
            string expectedHmac = "40 BC C3 0E 36 E2 06 06 AD 24 A3 20 8F 50 51 3D 38 33 08 E6 50 75 FE 09 84 FA 08 5B 80 6A AF 53";
            expectedHmac = expectedHmac.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHmac, Crypto.ByteArrayToHex(hmac));
        }

        // Add more unit tests for other methods


        [Fact]
        public void TransformFile_Test()
        {

            // Arrange
            string sourceFilePath = "TransformFile/input.txt";
            string encryptedFilePath = "TransformFile/encrypted.txt";
            string decryptedFilePath = "TransformFile/decrypted.txt";
            int operation = 1;


            // Act
            Crypto.TransformFile(sourceFilePath, encryptedFilePath, operation);
            Crypto.TransformFile(encryptedFilePath, decryptedFilePath, 0);

            // Assert
            string sourceText = File.ReadAllText(sourceFilePath);
            string decryptedText = File.ReadAllText(decryptedFilePath);
            Assert.Equal(sourceText, decryptedText);

        }


        [Fact]
        public void CBC_Test()
        {
            // Arrange
            string plainText = File.ReadAllText("CbcFile/input.txt");
            string key = "Trabzonspor01967";

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // Act
            byte[] encryptedBytes = Crypto.EncryptCBC(plainTextBytes, key);
            string decryptedText = Crypto.DecryptCBC(encryptedBytes, key);

            // Write encrypted text to a file
            File.WriteAllBytes("CbcFile/encrypted.txt", encryptedBytes);
            File.WriteAllText("CbcFile/ decrypted.txt",decryptedText);

            // Assert
            
            Assert.Equal(plainText, decryptedText);
        }


        [Fact]
        public void HOTP_Test()
        {
            // Arrange
            string key = "Trabzonspor1967";
            ulong counter = 123456;
            int digits = 6;
            int expectedOTP = 722997;

            // Act
            int actualOTP = Crypto.HOTP(key, counter, digits);

            // Assert
            Assert.Equal(expectedOTP, actualOTP);
        }
    }
}