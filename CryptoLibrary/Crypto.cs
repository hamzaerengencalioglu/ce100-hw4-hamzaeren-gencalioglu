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
        /// Converts a byte array to its hexadecimal representation.
        /// </summary>
        /// <param name="bytes">The byte array to convert.</param>
        /// <returns>The hexadecimal representation of the byte array.</returns>
        public static string ByteArrayToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
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



                    //Size the puffer as needed to add zero filling

                    // Write pufferi to the target file
                    File.WriteAllBytes(destFilePath, dataBuffer);

                    Console.WriteLine("The file was successfully encrypted and moved to the destination location: " + destFilePath);
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


                    // Decrypt the encrypted file and perform integrity checks here

                    // Write the decoded file to the destination file
                    File.WriteAllBytes(destFilePath, fileData);
                    Console.WriteLine("The file has been successfully decrypted and the integrity check is complete: " + destFilePath);
                }
                else
                {
                    Console.WriteLine("Invalid transaction code. The transaction code must be 0 or 1.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error occurred: " + ex.Message);
            }
        }

        /// <summary>
        /// Encrypts the provided plain text bytes using AES in CBC mode.
        /// </summary>
        /// <param name="TextBytes">The plain text bytes to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>The encrypted bytes.</returns>
        public static byte[] EncryptCBC(byte[] TextBytes, string key)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = new byte[16];
                aes.Mode = CipherMode.CBC;

                // Create an encryptor object using the AES key and IV
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                // Perform the encryption by transforming the plain text bytes
                byte[] encryptedBytes = encryptor.TransformFinalBlock(TextBytes, 0, TextBytes.Length);

                // Return the encrypted bytes
                return encryptedBytes;
            }
        }


        /// <summary>
        /// Decrypts the provided encrypted bytes using AES in CBC mode.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted bytes to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>The decrypted string.</returns>
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


        /// <summary>
        /// Generates a HMAC-based One-Time Password (HOTP) using the specified key and counter.
        /// </summary>
        /// <param name="key">The key used for generating the OTP.</param>
        /// <param name="counter">The counter value for the OTP generation.</param>
        /// <returns>The generated OTP as a string.</returns>



        public static int HOTP(string key, ulong counter, int digits = 6)
        {
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            HMACSHA1 hmac = new HMACSHA1(keyBytes);
            byte[] hash = hmac.ComputeHash(counterBytes);

            // Get the offset value from the last 4 bits of the hash
            int offset = hash[hash.Length - 1] & 0x0F;

            // Extract 4 bytes starting from the offset
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            // Calculate the OTP value by taking modulus with 10^digits
            int otp = binary % (int)Math.Pow(10, digits);

            return otp;
        }

    }
}