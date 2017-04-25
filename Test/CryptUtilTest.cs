


using System;
using NUnit.Framework;
using System.Text;

using MasterCard.Core;
using System.Collections.Generic;
using MasterCard.Core.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;

namespace TestMasterCard
{
	[TestFixture]
	public class CryptUtilTest
	{
		[Test]
		public void TestHexUnHex ()
		{
			String nonHexed = "andrea_rizzini@mastercard.com";
			String hexed = CryptUtil.HexEncode(nonHexed);

			byte[] nonHexedBytes = CryptUtil.HexDecode (hexed);
			String nonHexed2 = System.Text.Encoding.UTF8.GetString (nonHexedBytes);

			Assert.AreEqual (nonHexed, nonHexed2);

		}

		[Test]
		public void TestEncryptDecryptAES ()
		{
			String data = "andrea_rizzini@mastercard.com";
			Tuple<byte[], byte[], byte[]> tuple = CryptUtil.EncryptAES (System.Text.Encoding.UTF8.GetBytes(data), 128, CipherMode.CBC, PaddingMode.PKCS7);


			byte[] decryptedData = CryptUtil.DecryptAES (tuple.Item1, tuple.Item2, tuple.Item3, 128, CipherMode.CBC, PaddingMode.PKCS7);
			String data2 = System.Text.Encoding.UTF8.GetString (decryptedData);

			Assert.AreEqual (data, data2);

		}



        [Test]
		public void TestEncryptDecryptRSA () {

            string certPath = MasterCard.Core.Util.GetCurrenyAssemblyPath() + "\\Test\\certificate.p12";
            X509Certificate2 cert = new X509Certificate2(certPath , "", X509KeyStorageFlags.Exportable);

            var publicKey = cert.GetRSAPublicKey() as RSACng;
            var privateKey = cert.GetRSAPrivateKey() as RSACng;

			String data = "andrea_rizzini@mastercard.com";

			byte[] encryptedData = CryptUtil.EncrytptRSA (Encoding.UTF8.GetBytes (data), publicKey, RSAEncryptionPadding.OaepSHA256);

			Assert.NotNull (encryptedData);

			byte[] decryptedData = CryptUtil.DecryptRSA (encryptedData, privateKey, RSAEncryptionPadding.OaepSHA256);

			String dataOut = System.Text.Encoding.UTF8.GetString (decryptedData);

			Assert.AreEqual (data, dataOut);





		}


		[Test]
		public void TestFullEndToEndEncryptDecrypt () {

            string certPath = MasterCard.Core.Util.GetCurrenyAssemblyPath() + "\\Test\\certificate.p12";
            X509Certificate2 cert = new X509Certificate2(certPath , "", X509KeyStorageFlags.Exportable);

            var publicKey = cert.GetRSAPublicKey() as RSACng;
            var privateKey = cert.GetRSAPrivateKey() as RSACng;

			String data = "andrea_rizzini@mastercard.com";

			Tuple<byte[], byte[], byte[]> aesResult = CryptUtil.EncryptAES(Encoding.UTF8.GetBytes (data), 128, CipherMode.CBC, PaddingMode.PKCS7);
			byte[] ivBytes = aesResult.Item1;
			// 5) generate AES SecretKey
			byte[] secretKeyBytes = aesResult.Item2;
			// 6) encrypt payload
			byte[] encryptedDataBytes = aesResult.Item3;

			byte[] encryptedSecretKey = CryptUtil.EncrytptRSA (secretKeyBytes, publicKey, RSAEncryptionPadding.OaepSHA256);
			
			byte[] decryptedSecretKey = CryptUtil.DecryptRSA (encryptedSecretKey, privateKey, RSAEncryptionPadding.OaepSHA256);

			byte[] decryptedDataBytes = CryptUtil.DecryptAES(ivBytes, decryptedSecretKey, encryptedDataBytes, 128, CipherMode.CBC, PaddingMode.PKCS7);

			String dataOut = System.Text.Encoding.UTF8.GetString (decryptedDataBytes);

			Assert.AreEqual (data, dataOut);
		}

		[Test]
		public void TestHexEncodeDecode () {
				String data = "andrea_rizzini@mastercard.com";

				String encodeData =CryptUtil.Encode(Encoding.UTF8.GetBytes (data), MasterCard.Core.Security.Fle.DataEncoding.HEX);
				byte[] decodeDataBytes = CryptUtil.Decode(encodeData,MasterCard.Core.Security.Fle.DataEncoding.HEX);

				String dataOut = System.Text.Encoding.UTF8.GetString (decodeDataBytes);

				Assert.AreEqual (data, dataOut);
		}


	}
}

