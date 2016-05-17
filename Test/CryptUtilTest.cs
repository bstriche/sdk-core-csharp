#if DEBUG


using System;
using NUnit.Framework;
using System.Text;

using MasterCard.Core;
using System.Collections.Generic;
using MasterCard.Core.Security;

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
		public void TestEncryptDecrypt ()
		{
			String data = "andrea_rizzini@mastercard.com";
			Tuple<byte[], byte[], byte[]> tuple = CryptUtil.EncryptAES (data);


			byte[] decryptedData = CryptUtil.DecryptAES (tuple.Item1, tuple.Item2, tuple.Item3);
			String data2 = System.Text.Encoding.UTF8.GetString (decryptedData);

			Assert.AreEqual (data, data2);

		}




	}
}

#endif