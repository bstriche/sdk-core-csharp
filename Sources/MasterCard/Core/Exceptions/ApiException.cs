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

using MasterCard.Core.Model;
using System;
using System.Collections.Generic;
using System.Text;

namespace MasterCard.Core.Exceptions
{


    /// <summary>
    /// Base class for all API exceptions.
    /// </summary>
    public class ApiException : Exception
	{

		protected String source;
		protected String reasonCode;
		protected Boolean recoverable;
		protected String description;


		private SmartMap rawErrorData;

		/// <summary>
		///  Constructs an <code>ApiException</code> with no detail message.
		/// </summary>
		public ApiException() : base()
		{
		}

		/// <summary>
		///  Constructs an <code>ApiException</code> with the specified detail message. </summary>
		///  <param name="s"> the detail message. </param>
		public ApiException(string message) : base(message)
		{
		}


		/// <summary>
		/// Initializes a new instance of the <see cref="MasterCard.Core.Exceptions.ApiException"/> class.
		/// </summary>
		/// <param name="message">Message.</param>
		/// <param name="description">Description.</param>
		public ApiException(string message, string description) : base(message)
		{
			this.description = description;
		}

		/// <summary>
		///  Constructs an <code>ApiException</code> with the specified detail message
		///  and cause. </summary>
		///  <param name="s"> the detail message. </param>
		///  <param name="cause"> the detail message. </param>
		public ApiException(string message, Exception cause) : base(message, cause)
		{
		}

		/// <summary>
		///  Constructs an <code>ApiCommunicationException</code> with the specified cause. </summary>
		///  <param name="cause"> the detail message. </param>
		public ApiException(Exception cause) : base(cause.Message, cause)
		{
		}

		/// <summary>
		///  Constructs an <code>ApiException</code> with the specified details status
		///  and error data. </summary>
		///  <param name="status"> the HTTP status code </param>
		///  <param name="errorData"> a map representing the error details returned by the API.  The map is
		///  expected to contain <code>String</code> value for the key  <code>"reference"</code> and
		///  a map containing the detailed error data for the key <code>"key"</code>.  This map in turn
		///  is expected to contain <code>String</code> values for the keys
		///  <code>"code"</code> and <code>"message"</code>. </param>
		public ApiException(int status, IDictionary<String,Object> errorData) : base()
		{
			this.rawErrorData = new SmartMap(errorData, true);
			if (rawErrorData.ContainsKey ("Errors.Error")) {
					// this is a dictionary
					IDictionary<String, Object> error;

					if (rawErrorData["Errors.Error"].GetType() == typeof(List<Dictionary<String,Object>>))
					{
						error = ((Dictionary<String,Object>)rawErrorData["Errors.Error[0]"]);
					} else {
						error = (Dictionary<String,Object>)rawErrorData["Errors.Error"];
					}

                    SmartMap errorMap = new SmartMap(error, true);

                    if (errorMap.ContainsKey("Source"))
                    {
                        this.source = errorMap.Get("Source").ToString();
                    }
                    if (errorMap.ContainsKey("ReasonCode"))
                    {
                        this.reasonCode = errorMap.Get("ReasonCode").ToString();
                    }
                    if (errorMap.ContainsKey("Description"))
                    {
                        this.description = errorMap.Get("Description").ToString();
                    }
                    if (errorMap.ContainsKey("Recoverable"))
                    {
                        this.recoverable = Boolean.Parse(errorMap.Get("Recoverable").ToString());
                    }

            }
		}

		/// <summary>
		/// Returns the API error data for this exception. </summary>
		/// <returns> a map representing the error data for this exception (which may be <code>null</code>). </returns>
		public virtual SmartMap RawErrorData
		{
			get
			{
				return rawErrorData;
			}
		}

		/// <summary>
		/// Returns the reference string for this exception. </summary>
		/// <returns> an ID representing a unique reference for API error (which may be <code>null</code>). </returns>
		public override string Source
		{
			get
			{
				return source;
			}
		}

		/// <summary>
		/// Returns the error code for this exception. </summary>
		/// <returns>  a string representing the API error code (which may be <code>null</code>). </returns>
		public virtual string ReasonCode
		{
			get
			{
				return reasonCode;
			}
		}

		/// <summary>
		/// Returns the HTTP status code for this exception. </summary>
		/// <returns>  an integer representing the HTTP status code for this API error (or 0 if there is no status) </returns>
		public virtual Boolean Recoverable
		{
			get
			{
				return recoverable;
			}
		}

		/// <summary>
		/// Returns the string detail message for this exception. </summary>
		/// <returns>  a string representing the API error code or the message detail used to construct
		/// the exception (which may be <code>null</code>). </returns>
		public override string Message
		{
			get
			{
				if (description == null)
				{
					return base.Message;
				}
   
				return description;
			}
		}

		/// <summary>
		/// Returns a string describing the exception. </summary>
		/// <returns> a string describing the exception. </returns>
		public virtual string Describe()
		{
			StringBuilder sb = new StringBuilder();
			return sb.Append(this.GetType().Name).Append(": \"").Append(Message).Append("\" (Source: ").Append(Source).Append(", ReasonCode: ").Append(ReasonCode).Append(", Recoverable: ").Append(Recoverable).Append(")").ToString();
		}
	}

}