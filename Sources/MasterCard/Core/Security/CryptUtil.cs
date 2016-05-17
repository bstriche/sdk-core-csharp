using System;
using System.Text;
using System.Security.Cryptography;
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
		/// Bytes the array to hex string.
		/// </summary>
		/// <returns>The array to hex string.</returns>
		/// <param name="ba">Ba.</param>
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
			String hexString = BitConverter.ToString(ba);
			return hexString.Replace ("-", "");
		}

		public static Tuple<byte[], byte[], byte[]> EncryptAES(string toEncrypt)
		{
			var toEncryptBytes = Encoding.UTF8.GetBytes(toEncrypt);
			using (var provider = new AesCryptoServiceProvider())
			{
				provider.KeySize = 256;
				provider.GenerateKey ();
				provider.GenerateIV ();
				provider.Mode = CipherMode.CBC;
				provider.Padding = PaddingMode.PKCS7;
				using (var encryptor = provider.CreateEncryptor(provider.Key, provider.IV))
				{
					using (var ms = new MemoryStream())
					{
						//ms.Write(provider.IV, 0, 16);
						using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
						{
							cs.Write(toEncryptBytes, 0, toEncryptBytes.Length);
							cs.FlushFinalBlock();
						}

						return new Tuple<byte[], byte[], byte[]> (provider.IV, provider.Key, ms.ToArray ());
					}
				}
			}
		}


		public static byte[] DecryptAES(byte[] iv, byte[] encryptionKey, byte[] encryptedData) {
			using (var provider = new AesCryptoServiceProvider())
			{
				provider.KeySize = 256;
				provider.IV = iv;
				provider.Key = encryptionKey;
				provider.Mode = CipherMode.CBC;
				provider.Padding = PaddingMode.PKCS7;
				using (var ms = new MemoryStream(encryptedData))
				{
					//ms.Read(provider.IV, 0, 16);
					using (var decryptor = provider.CreateDecryptor(provider.Key, provider.IV))
					{
						using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
						{
							MemoryStream output = new MemoryStream();
							byte[] decrypted = new byte[1024];
							int byteCount = 0;
							while ((byteCount = cs.Read (decrypted, 0, decrypted.Length)) > 0) {
								output.Write(decrypted, 0, byteCount);
							}
							return output.ToArray ();
						}
					}
				}
			}
		}

	}
}

