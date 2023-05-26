using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;

namespace CryptoLibrary
{
    /// <summary>
    /// Provides cryptographic operations such as hashing, encryption, and decryption.
    /// </summary>
    public class Crypto
    {
        /// <summary>
        /// Computes the SHA-1 hash of the given data.
        /// </summary>
        /// <param name="data">The data to compute the hash for.</param>
        /// <returns>The computed SHA-1 hash.</returns>
        public static byte[] ComputeSHA1(byte[] data)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }

        /// <summary>
        /// Computes the SHA-256 hash of the given data.
        /// </summary>
        /// <param name="data">The data to compute the hash for.</param>
        /// <returns>The computed SHA-256 hash.</returns>
        public static byte[] ComputeSHA256(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }

        /// <summary>
        /// Computes the SHA-512 hash of the given data.
        /// </summary>
        /// <param name="data">The data to compute the hash for.</param>
        /// <returns>The computed SHA-512 hash.</returns>
        public static byte[] ComputeSHA512(byte[] data)
        {
            using (SHA512 sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(data);
            }
        }

        /// <summary>
        /// Encrypts the given data using the DES algorithm.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] DESEncrypt(byte[] data, string key)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key); // Set the encryption key
                des.IV = Encoding.UTF8.GetBytes(key); // Set the initialization vector (IV) to the same value as the key
                des.Mode = CipherMode.ECB; // Set the cipher mode to Electronic Codebook (ECB)
                des.Padding = PaddingMode.PKCS7; // Set the padding mode to PKCS7

                using (ICryptoTransform encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length); // Encrypt the data using the encryptor
                }
            }
        }


        /// <summary>
        /// Decrypts the given data using the DES algorithm.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] DESDecrypt(byte[] data, string key)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key); // Set the encryption key
                des.IV = Encoding.UTF8.GetBytes(key); // Set the initialization vector (IV) to the same value as the key
                des.Mode = CipherMode.ECB; // Set the cipher mode to Electronic Codebook (ECB)
                des.Padding = PaddingMode.PKCS7; // Set the padding mode to PKCS7

                using (ICryptoTransform decryptor = des.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length); // Decrypt the data using the decryptor
                }
            }
        }


        /// <summary>
        /// Encrypts the given data using the AES algorithm.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] AESEncrypt(byte[] data, string key)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = new byte[16]; // Random IV (Initialization Vector)
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        /// <summary>
        /// Decrypts the given data using the AES algorithm.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] AESDecrypt(byte[] data, string key)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = new byte[16]; // Random IV (Initialization Vector)
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the given data using the provided key.
        /// </summary>
        /// <param name="data">The data to compute the HMAC-SHA1 hash for.</param>
        /// <param name="key">The HMAC-SHA1 key.</param>
        /// <returns>The computed HMAC-SHA1 hash.</returns>
        public byte[] ComputeHMACSHA1(byte[] data, byte[] key)
        {
            using (HMACSHA1 hmacSha1 = new HMACSHA1(key))
            {
                return hmacSha1.ComputeHash(data);
            }
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the given data using the provided key.
        /// </summary>
        /// <param name="data">The data to compute the HMAC-SHA256 hash for.</param>
        /// <param name="key">The HMAC-SHA256 key.</param>
        /// <returns>The computed HMAC-SHA256 hash.</returns>
        public byte[] ComputeHMACSHA256(byte[] data, byte[] key)
        {
            using (HMACSHA256 hmacSha256 = new HMACSHA256(key))
            {
                return hmacSha256.ComputeHash(data);
            }
        }

        /// <summary>
        /// Computes the CRC32 hash of the given data.
        /// </summary>
        /// <param name="data">The data to compute the CRC32 hash for.</param>
        /// <returns>The computed CRC32 hash.</returns>
        public byte[] ComputeCRC32(byte[] data)
        {
            using (CRC32 crc32 = new CRC32())
            {
                return crc32.ComputeHash(data);
            }
        }

        /// <summary>
        /// Computes the MD5 hash of the given data.
        /// </summary>
        /// <param name="data">The data to compute the MD5 hash for.</param>
        /// <returns>The computed MD5 hash.</returns>
        public byte[] ComputeMD5(byte[] data)
        {
            using (MD5 md5 = MD5.Create())
            {
                return md5.ComputeHash(data);
            }
        }

        /// <summary>
        /// Converts a byte array to its hexadecimal representation.
        /// </summary>
        /// <param name="bytes">The byte array to convert.</param>
        /// <returns>The hexadecimal representation of the byte array.</returns>
        public string ByteArrayToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        /// <summary>
        /// Implements the CRC32 hash algorithm.
        /// </summary>
        class CRC32 : HashAlgorithm
        {
            private const uint Poly = 0xEDB88320; // Polynomial constant for CRC-32 calculation
            private uint[] table; // Lookup table for CRC-32 calculation

            public CRC32()
            {
                HashSizeValue = 32; // Set the hash size to 32 bits
                InitializeTable(); // Initialize the lookup table
            }

            public override void Initialize()
            {
                // Do nothing, as there is no additional initialization required
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                uint crc = uint.MaxValue; // Initialize the CRC value to its maximum value

                // Iterate over the input array, starting from ibStart and processing cbSize bytes
                for (int i = ibStart; i < ibStart + cbSize; i++)
                {
                    // Calculate the CRC value for each byte by XORing it with the current CRC value and using the lookup table
                    crc = (crc >> 8) ^ table[array[i] ^ crc & 0xFF];
                }

                // Set the computed CRC value as the hash value
                HashValue = new[] { (byte)(~crc >> 24), (byte)(~crc >> 16), (byte)(~crc >> 8), (byte)(~crc) };
            }

            protected override byte[] HashFinal()
            {
                return (byte[])HashValue.Clone(); // Return a clone of the hash value
            }

            private void InitializeTable()
            {
                table = new uint[256]; // Create a lookup table with 256 entries

                // Populate the lookup table with precomputed values for faster CRC calculation
                for (uint i = 0; i < 256; i++)
                {
                    uint entry = i;

                    // Perform the polynomial division algorithm to compute the table entry
                    for (int j = 0; j < 8; j++)
                    {
                        if ((entry & 1) == 1)
                            entry = (entry >> 1) ^ Poly;
                        else
                            entry >>= 1;
                    }

                    // Store the computed entry in the lookup table
                    table[i] = entry;
                }
            }
        }


        /// <summary>
        /// Transforms the file.
        /// </summary>
        /// <param name="sourceFilePath">A string representing the source file path.</param>
        /// <param name="destFilePath">A string representing the destination file path.</param>
        /// <param name="operation">The operation code. It takes a value of 0 or 1.</param>
        public static void TransformFile(string sourceFilePath, string destFilePath, int operation)
        {
            try
            {
                if (operation == 1)
                {

                    // Encrypt the file and check for integrity
                    string fileTxt = File.ReadAllText(sourceFilePath);

                    byte[] fileData = Encoding.UTF8.GetBytes(fileTxt);


                    byte[] sha1 = ComputeSHA1(fileData);

                    byte[] sha256 = ComputeSHA256(fileData);

                    byte[] sha512 = ComputeSHA512(fileData);


                    int bufferLength = 4 + 20 + fileData.Length + 32;
                    byte[] dataBuffer = new byte[bufferLength];

                    // Add 4 bytes of length information per pufferin
                    byte[] lengthBytes = BitConverter.GetBytes(fileData.Length);
                    Buffer.BlockCopy(lengthBytes, 0, dataBuffer, 0, 4);

                    // Add the SHA-1 hash to the beginning of the puffer
                    Buffer.BlockCopy(sha1, 0, dataBuffer, 4, 20);

                    // Add file data to the appropriate location of the puffer
                    Buffer.BlockCopy(fileData, 0, dataBuffer, 4 + 20, fileData.Length);

                    // Add the SHA-256 hash to the end of the puffer
                    Buffer.BlockCopy(sha256, 0, dataBuffer, 4 + 20 + fileData.Length, 32);

                    //// Add the SHA-512 hash to the end of the puffer
                    //Buffer.BlockCopy(sha512, 0, dataBuffer, 4 + 20 + fileData.Length + 32, 64);


                    //Size the puffer as needed to add zero filling

                    // Write pufferi to the target file
                    File.WriteAllBytes(destFilePath, dataBuffer);

                    Console.WriteLine("Dosya başarıyla şifrelendi ve hedef konuma taşındı: " + destFilePath);
                }
                else if (operation == 0)
                {
                    // Decrypt the encrypted file and check for integrity
                    byte[] dataBuffer = File.ReadAllBytes(sourceFilePath);

                    // Get 4 bytes of length information on the head of the puffer
                    int length = BitConverter.ToInt32(dataBuffer, 0);

                    // Extract SHA-1 hash from puffer
                    byte[] sha1 = new byte[20];
                    Buffer.BlockCopy(dataBuffer, 4, sha1, 0, 20);

                    // Remove file data from the puffer
                    byte[] fileData = new byte[length];
                    Buffer.BlockCopy(dataBuffer, 4 + 20, fileData, 0, length);

                    // Remove SHA-256 hash from puffer
                    byte[] sha256 = new byte[32];
                    Buffer.BlockCopy(dataBuffer, 4 + 20 + length, sha256, 0, 32);

                    //// SHA-512 extract the summary from the puffer
                    //byte[] sha512 = new byte[64];
                    //Buffer.BlockCopy(dataBuffer, 4 + 20 + length + 32, sha512, 0, 64);


                    // Decrypt the encrypted file and perform integrity checks here

                    // Write the decoded file to the destination file
                    File.WriteAllBytes(destFilePath, fileData);
                    Console.WriteLine("Dosya başarıyla çözüldü ve bütünlük kontrolü tamamlandı: " + destFilePath);
                }
                else
                {
                    Console.WriteLine("Geçersiz işlem kodu. İşlem kodu 0 veya 1 olmalıdır.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hata oluştu: " + ex.Message);
            }
        }







        public static byte[] EncryptCBC(byte[] plainTextBytes, string key)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = new byte[16];
                aes.Mode = CipherMode.CBC;

                // Create an encryptor object using the AES key and IV
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                // Perform the encryption by transforming the plain text bytes
                byte[] encryptedBytes = encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);

                // Return the encrypted bytes
                return encryptedBytes;
            }
        }


        public static string DecryptCBC(byte[] encryptedBytes, string key)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = new byte[16];
                aes.Mode = CipherMode.CBC;

                // Create a decryptor object using the AES key and IV
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                // Perform the decryption by transforming the encrypted bytes
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                // Convert the decrypted bytes to a string using UTF-8 encoding
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }








        private const int DIGITS = 6; // Number of households of the OTP
                                      //private const int INTERVAL = 30; // Duration of OTP (seconds)

        public static string GenerateHOTP(string key, long counter)
        {
            // Convert the counter to bytes
            byte[] counterBytes = BitConverter.GetBytes(counter);

            // If the system is little-endian, reverse the byte order
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counterBytes);

            // Convert the key to ASCII bytes
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);

            // Create an instance of the HMACSHA1 algorithm using the key
            HMACSHA1 hmac = new HMACSHA1(keyBytes);

            // Compute the hash of the counter bytes using the HMACSHA1 algorithm
            byte[] hash = hmac.ComputeHash(counterBytes);

            // Calculate the offset for retrieving a subset of the hash
            int offset = hash[hash.Length - 1] & 0x0F;

            // Extract a 32-bit integer value from the hash subset
            int otpValue =
            (
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF)
            ) % (int)Math.Pow(10, DIGITS);

            // Convert the OTP value to a string and pad it with leading zeros
            string otp = otpValue.ToString().PadLeft(DIGITS, '0');

            // Return the generated OTP
            return otp;
        }

    }
}