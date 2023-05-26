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
            Assert.Equal(expectedHash, ByteArrayToHex(hash));
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
            Assert.Equal(expectedHash, ByteArrayToHex(hash));
        }

        [Fact]
        public void ComputeSHA512_ValidData_ComputesCorrectHash()
        {
            // Arrange
            string filePath = File.ReadAllText("TransformFile/input.txt");
            byte[] data = Encoding.UTF8.GetBytes(filePath);

            // Act
            byte[] hash = Crypto.ComputeSHA512(data);

            // Assert
            string expectedHash = "7C 86 A9 86 04 A6 70 3A 3D 3D B0 E1 62 8E 3F B8 98 75 CA 3D 74 0B 91 50 C3 2C 29 19 A3 81 22 B0 82 E2 AF 14 27 8E 47 77 C5 38 07 0E 70 AF 7A 34 FA 75 D5 28 3F 08 66 30 57 6F 06 3C F3 28 7C 1C";
            expectedHash = expectedHash.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHash, ByteArrayToHex(hash));
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
            Assert.Equal(expectedHmac, ByteArrayToHex(hmac));
        }

        [Fact]
        public void ComputeHMACSHA256_ValidData_ComputesCorrectHMAC()
        {
            // Arrange
            string filePath = File.ReadAllText("TransformFile/input.txt");
            byte[] data = Encoding.UTF8.GetBytes(filePath);
            byte[] key = Encoding.UTF8.GetBytes("Trabzonspor"); 

            // Act
            byte[] hmac = crypto.ComputeHMACSHA256(data, key);

            // Assert
            string expectedHmac = "C3 D7 2D C2 16 8D 10 BD 49 30 86 64 89 D8 28 07 2D 6F 59 6D DA 44 B4 29 DC BA 41 35 87 7E 10 43";
            expectedHmac = expectedHmac.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHmac, ByteArrayToHex(hmac));
        }

        // Add more unit tests for other methods

        private string ByteArrayToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        [Fact]
        public void TransformFileTest()
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

            private const int DIGITS = 6;

            [Fact]
            public void GenerateHOTP_ValidParameters_ReturnsValidOTP()
            {
                // Arrange
                string key = "Trabzonspor";
                long counter = 123456;

                // Act
                string otp = Crypto.GenerateHOTP(key, counter);

                // Assert
                Assert.NotNull(otp);
                Assert.Equal(DIGITS, otp.Length);
                Assert.Matches("^[0-9]+$", otp);
            }

            [Fact]
            public void GenerateHOTP_WithDifferentCounters_ReturnsDifferentOTPs()
            {
                // Arrange
                string key = "Trabzonspor";
                long counter1 = 123456;
                long counter2 = 123457;

                // Act
                string otp1 = Crypto.GenerateHOTP(key, counter1);
                string otp2 = Crypto.GenerateHOTP(key, counter2);

                // Assert
                Assert.NotEqual(otp1, otp2);
            }

            [Fact]
            public void GenerateHOTP_WithDifferentKeys_ReturnsDifferentOTPs()
            {
                // Arrange
                string key1 = "Trabzonspor";
                string key2 = "tr123456789";
                long counter = 123456;

                // Act
                string otp1 = Crypto.GenerateHOTP(key1, counter);
                string otp2 = Crypto.GenerateHOTP(key2, counter);

                // Assert
                Assert.NotEqual(otp1, otp2);
            }

            [Fact]
            public void GenerateHOTP_WithLargeCounters_ReturnsValidOTP()
            {
                // Arrange
                string key = "Trabzonspor";
                long counter = long.MaxValue;

                // Act
                string otp = Crypto.GenerateHOTP(key, counter);

                // Assert
                Assert.NotNull(otp);
                Assert.Equal(DIGITS, otp.Length);
                Assert.Matches("^[0-9]+$", otp);
            }
        

    }
}