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
			ApiConfig.setP12 ("../../mcapi_sandbox_key.p12", "password");
			ApiConfig.setClientId ("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d");
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