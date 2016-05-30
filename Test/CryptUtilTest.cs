#if DEBUG


using System;
using NUnit.Framework;
using System.Text;

using MasterCard.Core;
using System.Collections.Generic;
using MasterCard.Core.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;

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
			Tuple<byte[], byte[], byte[]> tuple = CryptUtil.EncryptAES (System.Text.Encoding.UTF8.GetBytes(data));


			byte[] decryptedData = CryptUtil.DecryptAES (tuple.Item1, tuple.Item2, tuple.Item3);
			String data2 = System.Text.Encoding.UTF8.GetString (decryptedData);

			Assert.AreEqual (data, data2);

		}

		[Test]
		public void TestEncryptDecryptRSA () {
			X509Certificate2 cert = new X509Certificate2("../../Test/certificate.p12", "", X509KeyStorageFlags.Exportable);

			AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair (cert.PrivateKey as RSA);

			String data = "andrea_rizzini@mastercard.com";

			byte[] encryptedData = CryptUtil.EncrytptRSA (System.Text.Encoding.UTF8.GetBytes (data), keyPair.Public);

			Assert.NotNull (encryptedData);

			byte[] decryptedData = CryptUtil.DecryptRSA (encryptedData, keyPair.Private);

			String dataOut = System.Text.Encoding.UTF8.GetString (decryptedData);

			Assert.AreEqual (data, dataOut);





		}




	




	}
}

#endif