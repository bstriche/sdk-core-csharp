/*
 * Copyright 2016 MasterCard International.
 *
 * Redistribution and use in source and binary forms, with or without modification, are 
 * permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of 
 * conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of 
 * conditions and the following disclaimer in the documentation and/or other materials 
 * provided with the distribution.
 * Neither the name of the MasterCard International Incorporated nor the names of its 
 * contributors may be used to endorse or promote products derived from this software 
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 *
 */


using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MasterCard.Core.Security.Fle;
using System.Security.Authentication;
using System.IO;
using System.Linq;

namespace MasterCard.Core.Security
{
	public static class CryptUtil
	{
		/// <summary>
		/// Sanitizes the json.
		/// </summary>
		/// <returns>The json.</returns>
		/// <param name="payload">Payload.</param>
		public static String SanitizeJson(String payload) 
		{
			return payload.Replace ("\n", "").Replace ("\t", "").Replace ("\r", "").Replace (" ", "");
		}

		/// <summary>
		/// function to encode a byte array to a string representation.
		/// </summary>
		/// <returns>The string.</returns>
		/// <param name="bytes">Byte array containing the value to be encoded</param>
		/// <param name="encoding">Type of encoding</param>
		public static String Encode(byte[] bytes, DataEncoding encoding) {
			if (encoding == DataEncoding.HEX) {
				return HexEncode(bytes);
			} else {
				return Base64Encode(bytes);
			}
		}

		/// <summary>
		/// function to decode a String value to a byte[] representation.
		/// </summary>
		/// <returns>The byte[].</returns>
		/// <param name="value">String value to be decoded</param>
		/// <param name="decoding">Type of decoding</param>
		public static byte[] Decode(String value, DataEncoding decoding) {
			if (decoding == DataEncoding.HEX) {
				return HexDecode(value);
			} else {
				return Base64Decode(value);
			}
		}

		/// <summary>
		/// Bytes the array to base64 string.
		/// </summary>
		/// <returns>The string.</returns>
		/// <param name="bytes">Byte array containing the value to be encoded</param>
		public static String Base64Encode(byte[] bytes) {
			return System.Convert.ToBase64String(bytes);
		}

		/// <summary>
		/// Base64 string to byte array
		/// </summary>
		/// <returns>The string.</returns>
		/// <param name="bytes">Byte array containing the value to be encoded</param>
		public static byte[] Base64Decode(String base64String) {
			return System.Convert.FromBase64String(base64String);
		}


		/// <summary>
		/// Bytes the array to hex string.
		/// </summary>
		/// <returns>The array to hex string.</returns>
		/// <param name="hex">Hex.</param>
		public static byte[] HexDecode(String hex) 
		{
			return Enumerable.Range(0, hex.Length)
				.Where(x => x % 2 == 0)
				.Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
				.ToArray();
		}

		/// <summary>
		/// Convert Hex Strings to byte array.
		/// </summary>
		/// <returns>The to byte array.</returns>
		/// <param name="hex">Hex.</param>
		public static String HexEncode(String hex)
		{
			byte[] ba = Encoding.UTF8.GetBytes(hex);
			return HexEncode (ba);
		}


		/// <summary>
		/// Convert Hex Strings to byte array.
		/// </summary>
		/// <returns>The to byte array.</returns>
		/// <param name="hex">Hex.</param>
		public static String HexEncode(byte[] hexArray)
		{
			String hexString = BitConverter.ToString(hexArray);
			return hexString.Replace ("-", "");
		}

		public static String GetPublicCertFingerprint(X509Certificate2 cert) {
            Byte[] hashBytes;
            using (var hasher = new SHA256Managed()) {
                hashBytes = hasher.ComputeHash(cert.RawData);
            }
            return hashBytes.Aggregate(String.Empty, (str, hashByte) => str + hashByte.ToString("x2"));
        }


		public static Tuple<byte[], byte[], byte[]> EncryptAES(byte[] toEncrypt, int keySize, CipherMode mode, PaddingMode padding)
		{
            byte[] iv;
            byte[] key;
            byte[] data;
            using (var provider = new AesCryptoServiceProvider())
			{
				provider.KeySize = keySize;
				provider.GenerateKey ();
				provider.GenerateIV ();
				provider.Mode = mode;
				provider.Padding = padding;
				using (var encryptor = provider.CreateEncryptor(provider.Key, provider.IV))
				{
                    var ms = new MemoryStream();
					using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
					{
					    cs.Write(toEncrypt, 0, toEncrypt.Length);
						cs.FlushFinalBlock();
					}
                    iv = provider.IV; ;
                    key = provider.Key;
                    data = ms.ToArray();
				}
			}

            return new Tuple<byte[], byte[], byte[]>(iv, key, data);
        }


		public static byte[] DecryptAES(byte[] iv, byte[] encryptionKey, byte[] encryptedData, int keySize, CipherMode mode, PaddingMode padding) {
            byte[] result;
			using (var provider = new AesCryptoServiceProvider())
			{
				provider.KeySize = keySize;
				provider.IV = iv;
				provider.Key = encryptionKey;
				provider.Mode = mode;
				provider.Padding = padding;
				using (var decryptor = provider.CreateDecryptor(provider.Key, provider.IV))
				{
					using (var cs = new CryptoStream(new MemoryStream(encryptedData), decryptor, CryptoStreamMode.Read))
					{
						MemoryStream output = new MemoryStream();
						byte[] decrypted = new byte[1024];
						int byteCount = 0;
						while ((byteCount = cs.Read (decrypted, 0, decrypted.Length)) > 0) {
							output.Write(decrypted, 0, byteCount);
						}
						result= output.ToArray ();
					}
				}
			}
            return result;
		}

		public static RSACryptoServiceProvider GetRSAFromPrivateKeyString(string privateKey)
		{

			if (!privateKey.Contains ("-----BEGIN RSA PRIVATE KEY-----")) {
				throw new Exception ("Error loading private key, key is not a private key");
			}

			String tmpPrivateKey = privateKey.Replace ("-----BEGIN RSA PRIVATE KEY-----", ""); 
			tmpPrivateKey = tmpPrivateKey.Replace ("-----END RSA PRIVATE KEY-----", "");
			tmpPrivateKey = tmpPrivateKey.Replace (System.Environment.NewLine, "");

			var privateKeyBits = System.Convert.FromBase64String(tmpPrivateKey);

			var RSA = new RSACryptoServiceProvider();
			var RSAparams = new RSAParameters();

			using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
			{
				byte bt = 0;
				ushort twobytes = 0;
				twobytes = binr.ReadUInt16();
				if (twobytes == 0x8130)
					binr.ReadByte();
				else if (twobytes == 0x8230)
					binr.ReadInt16();
				else
					throw new Exception("Unexpected value read binr.ReadUInt16()");

				twobytes = binr.ReadUInt16();
				if (twobytes != 0x0102)
					throw new Exception("Unexpected version");

				bt = binr.ReadByte();
				if (bt != 0x00)
					throw new Exception("Unexpected value read binr.ReadByte()");

				RSAparams.Modulus = binr.ReadBytes(GetIntegerSize(binr));
				RSAparams.Exponent = binr.ReadBytes(GetIntegerSize(binr));
				RSAparams.D = binr.ReadBytes(GetIntegerSize(binr));
				RSAparams.P = binr.ReadBytes(GetIntegerSize(binr));
				RSAparams.Q = binr.ReadBytes(GetIntegerSize(binr));
				RSAparams.DP = binr.ReadBytes(GetIntegerSize(binr));
				RSAparams.DQ = binr.ReadBytes(GetIntegerSize(binr));
				RSAparams.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
			}

			RSA.ImportParameters(RSAparams);
			return RSA;
		}

		private static int GetIntegerSize(BinaryReader binr)
		{
			byte bt = 0;
			byte lowbyte = 0x00;
			byte highbyte = 0x00;
			int count = 0;
			bt = binr.ReadByte();
			if (bt != 0x02)
				return 0;
			bt = binr.ReadByte();

			if (bt == 0x81)
				count = binr.ReadByte();
			else
				if (bt == 0x82)
				{
					highbyte = binr.ReadByte();
					lowbyte = binr.ReadByte();
					byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
					count = BitConverter.ToInt32(modint, 0);
				}
				else
				{
					count = bt;
				}

			while (binr.ReadByte() == 0x00)
			{
				count -= 1;
			}
			binr.BaseStream.Seek(-1, SeekOrigin.Current);
			return count;
		}



        public static byte[] EncrytptRSA(byte[] data, RSA publicKey, RSAEncryptionPadding padding)
        {
            return publicKey.Encrypt(data, padding);
        }


        public static byte[] DecryptRSA(byte[] data, RSA privateKey, RSAEncryptionPadding padding)
        {
            return privateKey.Decrypt(data, padding);
        }
    }
}

