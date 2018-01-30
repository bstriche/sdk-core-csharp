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
using Test;


using MasterCard.Core;
using MasterCard.Core.Exceptions;
using MasterCard.Core.Model;
using MasterCard.Core.Security.OAuth;
using MasterCard.Core.Security.MDES;
using MasterCard.Core.Security.Installments;
using System.Threading;
using Environment = MasterCard.Core.Model.Constants.Environment;


namespace TestMasterCard
{


    [TestFixture()]
    public class EligibilityAndCalculatorTest : BaseTest
    {

        [SetUp]
        public void setup()
        {
            ApiConfig.SetDebug(true);
            var path = MasterCard.Core.Util.GetCurrenyAssemblyPath();

            var authentication = new OAuthAuthentication("L5BsiPgaF-O3qA36znUATgQXwJB6MRoMSdhjd7wt50c97279!50596e52466e3966546d434b7354584c4975693238513d3d", path + "\\Test\\mcapi_sandbox_key.p12", "test", "password");
            ApiConfig.SetAuthentication(authentication);

            var interceptor = new MDESCryptography(path + "\\Test\\mastercard_public.crt", path + "\\Test\\mastercard_private.pem");
            ApiConfig.AddCryptographyInterceptor(interceptor);

            var interceptor2 = new InstallmentCryptography(path + "\\Test\\installments_public.crt", null);
            ApiConfig.AddCryptographyInterceptor(interceptor2);

        }

        [Test()]
        public void Test_101_example_calculate_installment_I_request()
        {
            // 



            RequestMap map = new RequestMap();
            map.Set("calculatorReqData.primaryAccountNumber", "5204737010000412");
            map.Set("calculatorReqData.transactionAmount", "500");
            map.Set("calculatorReqData.currencyCode", "840");
            map.Set("calculatorReqData.noOfInstallments", "4");
            map.Set("calculatorReqData.merchCategCode", "1");
            map.Set("calculatorReqData.acqInstIdCode", "485");
            map.Set("calculatorReqData.cardAccpIdCode", "8692");
            map.Set("calculatorReqData.issuerConsentRequired", "N");

            List<string> ignoreAsserts = new List<string>();

            EligibilityAndCalculator response = EligibilityAndCalculator.Create(map);
            BaseTest.assertEqual(ignoreAsserts, response, "status", "Success");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.primaryAccountNumber", "0412");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.transactionAmount", "500");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.currencyCode", "840");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.merchCategCode", "1");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.acqInstIdCode", "485");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.cardAccpIdCode", "8692");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.installmentPaymentFormatI[0].noOfInstallments", "4");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.installmentPaymentFormatI[0].apr", "5.78");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.installmentPaymentFormatI[0].firstInstallmentAmount", "130.25");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.installmentPaymentFormatI[0].subSeqInstallmentAmount", "125.25");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.installmentPaymentFormatI[0].totalAmountDue", "506.00");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.installmentPaymentFormatI[0].interestRate", "1.00");
            BaseTest.assertEqual(ignoreAsserts, response, "calculatorRespData.installmentPaymentFormatI[0].installmentFee", "5.00000");

            BaseTest.putResponse("example_calculate_installment_I_request", response);

        }
    }

}