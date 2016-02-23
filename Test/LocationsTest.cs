using System;
using NUnit.Framework;
using MasterCard.Core;
using MasterCard.Core.Model;
using MasterCard.Core.Exceptions;
using MasterCard.Api.Locations;

namespace MasterCard.Test
{
	

	[TestFixture ()]
	public class LocationsTest
	{

		[SetUp]
		public void setup ()
		{
			ApiConfig.setP12 ("../../prod_key.p12", "password");
			ApiConfig.setClientId ("gVaoFbo86jmTfOB4NUyGKaAchVEU8ZVPalHQRLTxeaf750b6!414b543630362f426b4f6636415a5973656c33735661383d");
		}

		[Test ()]
		public void testCountries ()
		{
			
			//{"AccountInquiry":{"AccountNumber":"5343434343434343"}}
			ResourceList<Countries> countriesList = Countries.List ();
			Assert.AreEqual (2, countriesList.Count);

		}

	}


}