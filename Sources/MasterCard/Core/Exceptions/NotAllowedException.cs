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

namespace MasterCard.Core.Exceptions
{

	/// <summary>
	/// Not allowed exception.
	/// </summary>
	public class NotAllowedException : ApiException
	{

		/// <summary>
		///  Constructs an <code>NotAllowedException</code> with no detail message.
		/// </summary>
		public NotAllowedException() : base()
		{
		}

		/// <summary>
		///  Constructs an <code>NotAllowedException</code> with the specified detail message. </summary>
		///  <param name="s"> the detail message. </param>
		public NotAllowedException(string s) : base(s)
		{
		}

		/// <summary>
		///  Constructs an <code>NotAllowedException</code> with the specified detail message
		///  and cause. </summary>
		///  <param name="s"> the detail message. </param>
		///  <param name="cause"> the detail message. </param>
		public NotAllowedException(string s, Exception cause) : base(s, cause)
		{
		}

		/// <summary>
		///  Constructs an <code>NotAllowedException</code> with the specified cause. </summary>
		///  <param name="cause"> the detail message. </param>
		public NotAllowedException(Exception cause) : base(cause)
		{
		}

		/// <summary>
		///  Constructs an <code>NotAllowedException</code> with the specified status
		///  and error data. </summary>
		///  <param name="status"> the HTTP status code </param>
		///  <param name="errorData"> a map representing the error details returned by the API.  The map is
		///                   expected to contain <code>String</code> value for the key  <code>"reference"</code> and
		///                   a map containing the detailed error data for the key <code>"key"</code>.  This map in turn
		///                   is expected to contain <code>String</code> values for the keys
		///                   <code>"code"</code> and <code>"message"</code>. </param>
		///  <seealso cref=  String,Objectexception.ApiException </seealso>
		public NotAllowedException(int status, IDictionary<String,Object> errorData) : base(status, errorData)
		{
		}
	}


}