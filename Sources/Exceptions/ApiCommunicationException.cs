using System;

/*
 * Copyright 2015 MasterCard International.
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

namespace MasterCard.SDK.Exceptions
{

	/// <summary>
	/// Thrown to indicate that a communication error has occurred processing an API request.
	/// </summary>
	public class ApiCommunicationException : ApiException
	{

		/// <summary>
		///  Constructs an <code>ApiCommunicationException</code> with no detail message.
		/// </summary>
		public ApiCommunicationException() : base()
		{
		}

		/// <summary>
		///  Constructs an <code>ApiCommunicationException</code> with the specified detail message. </summary>
		///  <param name="s"> the detail message. </param>
		public ApiCommunicationException(string s) : base(s)
		{
		}

		/// <summary>
		///  Constructs an <code>ApiCommunicationException</code> with the specified detail message
		///  and cause. </summary>
		///  <param name="s"> the detail message. </param>
		///  <param name="cause"> the detail message. </param>
		public ApiCommunicationException(string s, Exception cause) : base(s, cause)
		{
		}

		/// <summary>
		///  Constructs an <code>ApiCommunicationException</code> with the specified cause. </summary>
		///  <param name="cause"> the detail message. </param>
		public ApiCommunicationException(Exception cause) : base(cause)
		{
		}
	}

}