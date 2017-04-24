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
using MasterCard.Core;
using MasterCard.Core.Exceptions;
using MasterCard.Core.Model;
using MasterCard.Core.Security;


namespace TestMasterCard
{
	public class GetToken : BaseObject
	{

		public GetToken(RequestMap bm) : base(bm)
		{
		}

		public GetToken() : base()
		{
		}

		private static readonly Dictionary<string, OperationConfig> _store = new Dictionary<string, OperationConfig>
		{
			{"61d50f85-0aca-4946-99f6-8822effae8b0", new OperationConfig("/mdes/digitization/#env/1/0/getToken", "create", new List<String> {  }, new List<String> {  })},
			
		};

		protected override OperationConfig GetOperationConfig(string operationUUID)
		{
			if (!_store.ContainsKey(operationUUID))
			{
				throw new System.ArgumentException("Invalid operationUUID supplied: " + operationUUID);
			}
			return _store[operationUUID];
		}

		protected override OperationMetadata GetOperationMetadata()
		{
			return new OperationMetadata("0.0.1", "https://sandbox.api.mastercard.com", "static");
		}

		/// <summary>
		/// Creates an object of type <code>GetToken</code>
		/// </summary>
		/// <param name="map">A RequestMap containing the required parameters to create a new object</praram>
		/// <returns> A GetToken object </returns>
        /// <exception cref="ApiException"> </exception>
		public static GetToken Create(RequestMap map)
		{
			return BaseObject.Execute("61d50f85-0aca-4946-99f6-8822effae8b0", new GetToken(map));
		}





	}
}


