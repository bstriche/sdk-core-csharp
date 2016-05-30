using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

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


		public static Tuple<byte[], byte[], byte[]> EncryptAES(byte[] toEncrypt)
		{
			var toEncryptBytes = toEncrypt;
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
			


		public static byte[] EncrytptRSA(byte[] data, AsymmetricKeyParameter publicKey) {

			String algorithm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
			IBufferedCipher cipher = CipherUtilities.GetCipher (algorithm);
			cipher.Init (true, publicKey);
			return cipher.DoFinal (data);

		}


		public static byte[] DecryptRSA(byte[] data, AsymmetricKeyParameter privateKey) {
			String algorithm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
			IBufferedCipher cipher = CipherUtilities.GetCipher (algorithm);
			cipher.Init (false, privateKey);
			return cipher.DoFinal (data);
		}


//		private static byte[] ExportPrivateKey(RSACryptoServiceProvider csp)
//		{
//			if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
//			var parameters = csp.ExportParameters(true);
//			using (var stream = new MemoryStream())
//			{
//				var writer = new BinaryWriter(stream);
//				writer.Write((byte)0x30); // SEQUENCE
//				using (var innerStream = new MemoryStream())
//				{
//					var innerWriter = new BinaryWriter(innerStream);
//					EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
//					EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
//					EncodeIntegerBigEndian(innerWriter, parameters.D);
//					EncodeIntegerBigEndian(innerWriter, parameters.P);
//					EncodeIntegerBigEndian(innerWriter, parameters.Q);
//					EncodeIntegerBigEndian(innerWriter, parameters.DP);
//					EncodeIntegerBigEndian(innerWriter, parameters.DQ);
//					EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
//					var length = (int)innerStream.Length;
//					EncodeLength(writer, length);
//					writer.Write(innerStream.GetBuffer(), 0, length);
//				}
//
//				stream.Position = 0;
//				return stream.ToArray ();
//			}
//		}
//
//
//		public static byte[] ExportPublicKey(RSACryptoServiceProvider csp)
//		{
//			var parameters = csp.ExportParameters(false);
//			using (var stream = new MemoryStream())
//			{
//				var writer = new BinaryWriter(stream);
//				writer.Write((byte)0x30); // SEQUENCE
//				using (var innerStream = new MemoryStream())
//				{
//					var innerWriter = new BinaryWriter(innerStream);
//					EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
//					EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
//
//					//All Parameter Must Have Value so Set Other Parameter Value Whit Invalid Data  (for keeping Key Structure  use "parameters.Exponent" value for invalid data)
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.D
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.P
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.Q
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.DP
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.DQ
//					EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.InverseQ
//
//					var length = (int)innerStream.Length;
//					EncodeLength(writer, length);
//					writer.Write(innerStream.GetBuffer(), 0, length);
//				}
//				stream.Position = 0;
//				return stream.ToArray ();
//			}
//		}
//
//		private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
//		{
//			stream.Write((byte)0x02); // INTEGER
//			var prefixZeros = 0;
//			for (var i = 0; i < value.Length; i++)
//			{
//				if (value[i] != 0) break;
//				prefixZeros++;
//			}
//			if (value.Length - prefixZeros == 0)
//			{
//				EncodeLength(stream, 1);
//				stream.Write((byte)0);
//			}
//			else
//			{
//				if (forceUnsigned && value[prefixZeros] > 0x7f)
//				{
//					// Add a prefix zero to force unsigned if the MSB is 1
//					EncodeLength(stream, value.Length - prefixZeros + 1);
//					stream.Write((byte)0);
//				}
//				else
//				{
//					EncodeLength(stream, value.Length - prefixZeros);
//				}
//				for (var i = prefixZeros; i < value.Length; i++)
//				{
//					stream.Write(value[i]);
//				}
//			}
//		}
//
//		private static void EncodeLength(BinaryWriter stream, int length)
//		{
//			if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
//			if (length < 0x80)
//			{
//				// Short form
//				stream.Write((byte)length);
//			}
//			else
//			{
//				// Long form
//				var temp = length;
//				var bytesRequired = 0;
//				while (temp > 0)
//				{
//					temp >>= 8;
//					bytesRequired++;
//				}
//				stream.Write((byte)(bytesRequired | 0x80));
//				for (var i = bytesRequired - 1; i >= 0; i--)
//				{
//					stream.Write((byte)(length >> (8 * i) & 0xff));
//				}
//			}
//		}
	}
}

