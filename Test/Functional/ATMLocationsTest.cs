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
using System.Collections.Generic;
using NUnit.Framework;


using MasterCard.Core;
using MasterCard.Core.Exceptions;
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using MasterCard.Core.Security.MDES;



namespace TestMasterCard
{


	[TestFixture ()]
	public class ATMLocationsTest
	{

		[SetUp]
		public void setup ()
		{
            var currentPath = MasterCard.Core.Util.GetCurrenyAssemblyPath();
            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", currentPath + "\\Test\\mcapi_sandbox_key.p12", "test", "password");
            ApiConfig.SetAuthentication(authentication);
            ApiConfig.SetSandbox(true);
        }


        
            
            
            
            
            
            
                        

        [Test ()]
        public void atm_locations_Test()
        {
            RequestMap parameters = new RequestMap();
            
            parameters.Set ("PageOffset", "0");
            parameters.Set ("PageLength", "5");
            parameters.Set ("PostalCode", "11101");
            
            

            ATMLocations response = ATMLocations.Query(parameters);
            TestUtil.assert("0", response["Atms.PageOffset"]);
            TestUtil.assert("26", response["Atms.TotalCount"]);
            TestUtil.assert("Sandbox ATM Location 1", response["Atms.Atm[0].Location.Name"]);
            //TestUtil.assert("0.9320591049747101", response["Atms.Atm[0].Location.Distance"]);
            TestUtil.assert("MILE", response["Atms.Atm[0].Location.DistanceUnit"]);
            TestUtil.assert("4201 Leverton Cove Road", response["Atms.Atm[0].Location.Address.Line1"]);
            TestUtil.assert("SPRINGFIELD", response["Atms.Atm[0].Location.Address.City"]);
            TestUtil.assert("11101", response["Atms.Atm[0].Location.Address.PostalCode"]);
            TestUtil.assert("UYQQQQ", response["Atms.Atm[0].Location.Address.CountrySubdivision.Name"]);
            TestUtil.assert("QQ", response["Atms.Atm[0].Location.Address.CountrySubdivision.Code"]);
            TestUtil.assert("UYQQQRR", response["Atms.Atm[0].Location.Address.Country.Name"]);
            TestUtil.assert("UYQ", response["Atms.Atm[0].Location.Address.Country.Code"]);
            TestUtil.assert("38.76006576913497", response["Atms.Atm[0].Location.Point.Latitude"]);
            TestUtil.assert("-90.74615107952418", response["Atms.Atm[0].Location.Point.Longitude"]);
            TestUtil.assert("OTHER", response["Atms.Atm[0].Location.LocationType.Type"]);
            TestUtil.assert("NO", response["Atms.Atm[0].HandicapAccessible"]);
            TestUtil.assert("NO", response["Atms.Atm[0].Camera"]);
            TestUtil.assert("UNKNOWN", response["Atms.Atm[0].Availability"]);
            TestUtil.assert("UNKNOWN", response["Atms.Atm[0].AccessFees"]);
            TestUtil.assert("Sandbox ATM 1", response["Atms.Atm[0].Owner"]);
            TestUtil.assert("NO", response["Atms.Atm[0].SharedDeposit"]);
            TestUtil.assert("NO", response["Atms.Atm[0].SurchargeFreeAlliance"]);
            TestUtil.assert("DOES_NOT_PARTICIPATE_IN_SFA", response["Atms.Atm[0].SurchargeFreeAllianceNetwork"]);
            TestUtil.assert("Sandbox", response["Atms.Atm[0].Sponsor"]);
            TestUtil.assert("1", response["Atms.Atm[0].SupportEMV"]);
            TestUtil.assert("1", response["Atms.Atm[0].InternationalMaestroAccepted"]);


        }
        
            
        

    }
}
