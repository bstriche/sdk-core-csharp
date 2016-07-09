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


namespace TestMasterCard
{


	[TestFixture ()]
	public class InsightsTest
	{

		[SetUp]
		public void setup ()
		{
            var authentication = new OAuthAuthentication ("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", "../../mcapi_sandbox_key.p12", "alias", "password");
            ApiConfig.setAuthentication (authentication);
		}

        
            
            
            
            
            
            
                        

        [Test ()]
        public void example_insights_Test()
        {
            RequestMap parameters = new RequestMap();
            
            parameters.Set ("Period", "");
            parameters.Set ("CurrentRow", "1");
            parameters.Set ("Sector", "");
            parameters.Set ("Offset", "25");
            parameters.Set ("Country", "US");
            parameters.Set ("Ecomm", "");
            
            

            Insights response = Insights.Query(parameters);
            Assert.That("11/30/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.033862493", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].SalesIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].Sector"]).IgnoreCase);
            Assert.That("11/9/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("11/30/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.083439694", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].TransactionsIndex"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].Period"]).IgnoreCase);
            Assert.That("0.064810496", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].TransactionsIndex"]).IgnoreCase);
            Assert.That("11/2/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].BeginDate"]).IgnoreCase);
            Assert.That("7/13/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].Ecomm"]).IgnoreCase);
            Assert.That("8/10/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].BeginDate"]).IgnoreCase);
            Assert.That("12/27/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].EndDate"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].Period"]).IgnoreCase);
            Assert.That("12/30/2012", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("4666390.074", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].SalesIndexValue"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].Country"]).IgnoreCase);
            Assert.That("11/2/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].BeginDate"]).IgnoreCase);
            Assert.That("-0.003968331", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].AverageTicketIndex"]).IgnoreCase);
            Assert.That("14586848.49", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].SalesIndexValue"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].Sector"]).IgnoreCase);
            Assert.That("0.089399728", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].TransactionsIndex"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].Period"]).IgnoreCase);
            Assert.That("0.070222262", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].SalesIndex"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].Country"]).IgnoreCase);
            Assert.That("4610930.63", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].SalesIndexValue"]).IgnoreCase);
            Assert.That("3/23/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].BeginDate"]).IgnoreCase);
            Assert.That("-0.00577838", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].AverageTicketIndex"]).IgnoreCase);
            Assert.That("12/7/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("Success", Is.EqualTo(response["SectorRecordList.Message"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].Ecomm"]).IgnoreCase);
            Assert.That("11/3/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("0.011748007", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].SalesIndex"]).IgnoreCase);
            Assert.That("4895914.274", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].SalesIndexValue"]).IgnoreCase);
            Assert.That("12/14/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].BeginDate"]).IgnoreCase);
            Assert.That("12/8/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("0.089992028", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].SalesIndex"]).IgnoreCase);
            Assert.That("0.083737514", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].SalesIndex"]).IgnoreCase);
            Assert.That("11/1/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].EndDate"]).IgnoreCase);
            Assert.That("4463445.742", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].SalesIndexValue"]).IgnoreCase);
            Assert.That("0.035568928", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].SalesIndex"]).IgnoreCase);
            Assert.That("Quarterly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].Period"]).IgnoreCase);
            Assert.That("-0.000125706", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].AverageTicketIndex"]).IgnoreCase);
            Assert.That("11/17/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("2/24/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("12/13/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].EndDate"]).IgnoreCase);
            Assert.That("0.000253361", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].AverageTicketIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].Sector"]).IgnoreCase);
            Assert.That("0.095643662", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].TransactionsIndex"]).IgnoreCase);
            Assert.That("12/28/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].BeginDate"]).IgnoreCase);
            Assert.That("1/26/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].Ecomm"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].Period"]).IgnoreCase);
            Assert.That("0.077937282", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].SalesIndex"]).IgnoreCase);
            Assert.That("9/7/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].BeginDate"]).IgnoreCase);
            Assert.That("0.004143999", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].AverageTicketIndex"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].Ecomm"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].Country"]).IgnoreCase);
            Assert.That("13956974.12", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].SalesIndexValue"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].Sector"]).IgnoreCase);
            Assert.That("0.086861262", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].TransactionsIndex"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].Country"]).IgnoreCase);
            Assert.That("1/27/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("0.102417809", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].TransactionsIndex"]).IgnoreCase);
            Assert.That("5390273.888", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].SalesIndexValue"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].Country"]).IgnoreCase);
            Assert.That("0.080227189", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].SalesIndex"]).IgnoreCase);
            Assert.That("5/18/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].BeginDate"]).IgnoreCase);
            Assert.That("11/30/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].BeginDate"]).IgnoreCase);
            Assert.That("10/5/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].BeginDate"]).IgnoreCase);
            Assert.That("0.117574514", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].SalesIndex"]).IgnoreCase);
            Assert.That("11/29/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].EndDate"]).IgnoreCase);
            Assert.That("11/22/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].EndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].Ecomm"]).IgnoreCase);
            Assert.That("0.046899887", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].TransactionsIndex"]).IgnoreCase);
            Assert.That("1/3/2015", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].EndDate"]).IgnoreCase);
            Assert.That("0.049201983", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].SalesIndex"]).IgnoreCase);
            Assert.That("Quarterly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].Period"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].Ecomm"]).IgnoreCase);
            Assert.That("11/24/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("0.010714415", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].SalesIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].Sector"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].Period"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].Period"]).IgnoreCase);
            Assert.That("22029890.42", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].SalesIndexValue"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].Country"]).IgnoreCase);
            Assert.That("6/15/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].BeginDate"]).IgnoreCase);
            Assert.That("-0.001106025", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].AverageTicketIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].Sector"]).IgnoreCase);
            Assert.That("4/20/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].Country"]).IgnoreCase);
            Assert.That("11/2/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.034610621", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].TransactionsIndex"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].Period"]).IgnoreCase);
            Assert.That("11/16/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].Country"]).IgnoreCase);
            Assert.That("0.081004826", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].TransactionsIndex"]).IgnoreCase);
            Assert.That("12/29/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].BeginDate"]).IgnoreCase);
            Assert.That("0.050445564", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].TransactionsIndex"]).IgnoreCase);
            Assert.That("1332036.912", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].SalesIndexValue"]).IgnoreCase);
            Assert.That("12/29/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].Country"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].Sector"]).IgnoreCase);
            Assert.That("12/22/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].Country"]).IgnoreCase);
            Assert.That("0.081037693", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].SalesIndex"]).IgnoreCase);
            Assert.That("Quarterly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].Period"]).IgnoreCase);
            Assert.That("3/23/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].BeginDate"]).IgnoreCase);
            Assert.That("0.088906782", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].TransactionsIndex"]).IgnoreCase);
            Assert.That("9/6/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].EndDate"]).IgnoreCase);
            Assert.That("9/7/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("11/29/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].EndDate"]).IgnoreCase);
            Assert.That("1/26/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].BeginDate"]).IgnoreCase);
            Assert.That("11/9/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].BeginDate"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].Period"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].Ecomm"]).IgnoreCase);
            Assert.That("1350468.126", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].SalesIndexValue"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].Ecomm"]).IgnoreCase);
            Assert.That("0.06399651", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].SalesIndex"]).IgnoreCase);
            Assert.That("4716264.801", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].SalesIndexValue"]).IgnoreCase);
            Assert.That("4776139.381", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].SalesIndexValue"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].Ecomm"]).IgnoreCase);
            Assert.That("1789039.367", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].SalesIndexValue"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].Country"]).IgnoreCase);
            Assert.That("-0.009346738", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].AverageTicketIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].Sector"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].Country"]).IgnoreCase);
            Assert.That("0.076812652", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].SalesIndex"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].Ecomm"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].Sector"]).IgnoreCase);
            Assert.That("1/4/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.077862316", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].SalesIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].Sector"]).IgnoreCase);
            Assert.That("0.096327022", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].TransactionsIndex"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].Ecomm"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].Ecomm"]).IgnoreCase);
            Assert.That("11/16/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].BeginDate"]).IgnoreCase);
            Assert.That("-0.000775331", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].AverageTicketIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].Sector"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].Sector"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].Sector"]).IgnoreCase);
            Assert.That("13768292.67", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].SalesIndexValue"]).IgnoreCase);
            Assert.That("-0.009014519", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].AverageTicketIndex"]).IgnoreCase);
            Assert.That("3/22/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].EndDate"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].Period"]).IgnoreCase);
            Assert.That("0.064357166", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].SalesIndex"]).IgnoreCase);
            Assert.That("6/16/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("0.026920473", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].TransactionsIndex"]).IgnoreCase);
            Assert.That("-0.010073866", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].AverageTicketIndex"]).IgnoreCase);
            Assert.That("-0.000552344", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].AverageTicketIndex"]).IgnoreCase);
            Assert.That("9/7/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].BeginDate"]).IgnoreCase);
            Assert.That("10/5/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("11/23/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].BeginDate"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].Sector"]).IgnoreCase);
            Assert.That("1185950.237", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].SalesIndexValue"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].Ecomm"]).IgnoreCase);
            Assert.That("12/21/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].BeginDate"]).IgnoreCase);
            Assert.That("0.077620825", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].TransactionsIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].Sector"]).IgnoreCase);
            Assert.That("4574319.24", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].SalesIndexValue"]).IgnoreCase);
            Assert.That("6/14/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].EndDate"]).IgnoreCase);
            Assert.That("3/24/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].Sector"]).IgnoreCase);
            Assert.That("-0.022654487", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].AverageTicketIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].Sector"]).IgnoreCase);
            Assert.That("1193299.96", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].SalesIndexValue"]).IgnoreCase);
            Assert.That("12/28/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.099764512", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].SalesIndex"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].Country"]).IgnoreCase);
            Assert.That("-0.0498328", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].AverageTicketIndex"]).IgnoreCase);
            Assert.That("0.026791383", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].SalesIndex"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].Period"]).IgnoreCase);
            Assert.That("2/23/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.13335406", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].SalesIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].Sector"]).IgnoreCase);
            Assert.That("8/11/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("1/4/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("6/14/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].EndDate"]).IgnoreCase);
            Assert.That("11/3/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("11/15/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].EndDate"]).IgnoreCase);
            Assert.That("12/30/2012", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].Period"]).IgnoreCase);
            Assert.That("1244980.145", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].SalesIndexValue"]).IgnoreCase);
            Assert.That("4938904.288", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].SalesIndexValue"]).IgnoreCase);
            Assert.That("0.094649123", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].TransactionsIndex"]).IgnoreCase);
            Assert.That("12/15/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].Period"]).IgnoreCase);
            Assert.That("4/19/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].EndDate"]).IgnoreCase);
            Assert.That("0.081208216", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].TransactionsIndex"]).IgnoreCase);
            Assert.That("11/10/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("9/8/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].Ecomm"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].Ecomm"]).IgnoreCase);
            Assert.That("-0.007884916", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].AverageTicketIndex"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].Country"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].Period"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].Ecomm"]).IgnoreCase);
            Assert.That("0.074896863", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].SalesIndex"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].Period"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].Ecomm"]).IgnoreCase);
            Assert.That("-0.010866807", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].AverageTicketIndex"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].Country"]).IgnoreCase);
            Assert.That("4716899.304", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].SalesIndexValue"]).IgnoreCase);
            Assert.That("5/18/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].Ecomm"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].Ecomm"]).IgnoreCase);
            Assert.That("7/12/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].EndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].Ecomm"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].Country"]).IgnoreCase);
            Assert.That("70", Is.EqualTo(response["SectorRecordList.Count"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].Ecomm"]).IgnoreCase);
            Assert.That("0.093480745", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].SalesIndex"]).IgnoreCase);
            Assert.That("9/7/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].Period"]).IgnoreCase);
            Assert.That("-0.008106785", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].AverageTicketIndex"]).IgnoreCase);
            Assert.That("4693916.302", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].SalesIndexValue"]).IgnoreCase);
            Assert.That("1/3/2015", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].EndDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].Country"]).IgnoreCase);
            Assert.That("0.091237201", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[24].TransactionsIndex"]).IgnoreCase);
            Assert.That("8/10/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.134608966", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].TransactionsIndex"]).IgnoreCase);
            Assert.That("-0.015309221", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].AverageTicketIndex"]).IgnoreCase);
            Assert.That("Weekly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].Period"]).IgnoreCase);
            Assert.That("0.022281044", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].SalesIndex"]).IgnoreCase);
            Assert.That("11/23/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].Period"]).IgnoreCase);
            Assert.That("11/30/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].BeginDate"]).IgnoreCase);
            Assert.That("0.100372296", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].TransactionsIndex"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].Country"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].Country"]).IgnoreCase);
            Assert.That("10/6/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("12/6/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].EndDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[2].Country"]).IgnoreCase);
            Assert.That("2/22/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].EndDate"]).IgnoreCase);
            Assert.That("-0.029602284", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].AverageTicketIndex"]).IgnoreCase);
            Assert.That("1601525.658", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].SalesIndexValue"]).IgnoreCase);
            Assert.That("-0.011554139", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].AverageTicketIndex"]).IgnoreCase);
            Assert.That("0.035983443", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].TransactionsIndex"]).IgnoreCase);
            Assert.That("1/3/2015", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].EndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].Ecomm"]).IgnoreCase);
            Assert.That("-0.012642959", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].AverageTicketIndex"]).IgnoreCase);
            Assert.That("9/8/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].Sector"]).IgnoreCase);
            Assert.That("6/15/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].Ecomm"]).IgnoreCase);
            Assert.That("3/23/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("7/14/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("0.005715632", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].AverageTicketIndex"]).IgnoreCase);
            Assert.That("8/9/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].EndDate"]).IgnoreCase);
            Assert.That("7146577.851", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].SalesIndexValue"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].Ecomm"]).IgnoreCase);
            Assert.That("9/6/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].EndDate"]).IgnoreCase);
            Assert.That("11/8/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].EndDate"]).IgnoreCase);
            Assert.That("-0.03782314", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].AverageTicketIndex"]).IgnoreCase);
            Assert.That("-0.042517568", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].AverageTicketIndex"]).IgnoreCase);
            Assert.That("12/1/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].Country"]).IgnoreCase);
            Assert.That("0.097922083", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].TransactionsIndex"]).IgnoreCase);
            Assert.That("0.059573011", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[21].TransactionsIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].Sector"]).IgnoreCase);
            Assert.That("3/24/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("1/25/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].EndDate"]).IgnoreCase);
            Assert.That("12/14/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("12/29/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].BeginDate"]).IgnoreCase);
            Assert.That("6/16/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].Ecomm"]).IgnoreCase);
            Assert.That("0.074039112", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].TransactionsIndex"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].Sector"]).IgnoreCase);
            Assert.That("-0.002047282", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].AverageTicketIndex"]).IgnoreCase);
            Assert.That("0.1129624", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].TransactionsIndex"]).IgnoreCase);
            Assert.That("1518287.003", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].SalesIndexValue"]).IgnoreCase);
            Assert.That("4/20/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].BeginDate"]).IgnoreCase);
            Assert.That("0.048107305", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].SalesIndex"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].Period"]).IgnoreCase);
            Assert.That("12/7/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].BeginDate"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[17].Sector"]).IgnoreCase);
            Assert.That("0.052883582", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].SalesIndex"]).IgnoreCase);
            Assert.That("6/15/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("12/1/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[9].Period"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[13].Sector"]).IgnoreCase);
            Assert.That("1/4/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[0].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("0.098200253", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].SalesIndex"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[25].Country"]).IgnoreCase);
            Assert.That("7/13/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].BeginDate"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[11].Period"]).IgnoreCase);
            Assert.That("4/21/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("-0.011917118", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].AverageTicketIndex"]).IgnoreCase);
            Assert.That("5/17/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[8].EndDate"]).IgnoreCase);
            Assert.That("1321264.332", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].SalesIndexValue"]).IgnoreCase);
            Assert.That("10/4/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[3].EndDate"]).IgnoreCase);
            Assert.That("6/15/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].BeginDate"]).IgnoreCase);
            Assert.That("0.127285919", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].SalesIndex"]).IgnoreCase);
            Assert.That("5/19/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].YearBeforeBeginDate"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[20].Country"]).IgnoreCase);
            Assert.That("0.131777185", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[18].TransactionsIndex"]).IgnoreCase);
            Assert.That("-0.002907027", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[4].AverageTicketIndex"]).IgnoreCase);
            Assert.That("Quarterly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[14].Period"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].Sector"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[1].Sector"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[7].Period"]).IgnoreCase);
            Assert.That("4752029.923", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[5].SalesIndexValue"]).IgnoreCase);
            Assert.That("0.081065373", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].TransactionsIndex"]).IgnoreCase);
            Assert.That("12/21/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("3/22/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].EndDate"]).IgnoreCase);
            Assert.That("NO", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].Ecomm"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[15].Country"]).IgnoreCase);
            Assert.That("U.S. Natural and Organic Grocery Stores", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[6].Sector"]).IgnoreCase);
            Assert.That("3/23/2013", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[16].YearBeforeEndDate"]).IgnoreCase);
            Assert.That("2/23/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[10].BeginDate"]).IgnoreCase);
            Assert.That("Monthly", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[12].Period"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[23].Country"]).IgnoreCase);
            Assert.That("US", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[22].Country"]).IgnoreCase);
            Assert.That("12/20/2014", Is.EqualTo(response["SectorRecordList.SectorRecordArray.SectorRecord[19].EndDate"]).IgnoreCase);
            

        }
        
            
        
    }
}
