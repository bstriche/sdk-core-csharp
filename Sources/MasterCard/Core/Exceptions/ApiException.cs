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
		protected int httpStatus = 0;
		protected List<Dictionary<String,Object>> errors = new List<Dictionary<String,Object>>();


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
		public ApiException(int status, Object errorData) : base()
		{
			this.httpStatus = status;
			ParseErrors(errorData);
			ParseFirstErrorToMemberVariables();
		}


		protected void ParseErrors(Object response) {
			List<Dictionary<String,Object>> tmpList = new List<Dictionary<String,Object>>();
			
			if (response is List<Object>) {
				tmpList.AddRange(SmartMap.CastToListOfDictionary(response));
			} else {
				tmpList.Add(SmartMap.CastToDictionary(response));
			}

			foreach (Dictionary<String,Object> tmpErrorMap in tmpList) {

				SmartMap tmpCaseInsensitiveMap = new SmartMap(tmpErrorMap, true);
				try {
					if (tmpCaseInsensitiveMap.ContainsKey("Errors.Error.Description")) {
						//errors object with a list of error object
						Dictionary<String,Object> tmpErrorObj = (Dictionary<String,Object>) tmpCaseInsensitiveMap.Get("Errors.Error");
						AddError(tmpErrorObj);
						continue;
					}
				} catch (Exception) {

				}

				try {
					if (tmpCaseInsensitiveMap.ContainsKey("Errors.Error[0].Description")) {
						//errors object with a list of error object
						List<Dictionary<String,Object>> tmpErrorList = (List<Dictionary<String,Object>>) tmpCaseInsensitiveMap.Get("Errors.Error");
						AddError(tmpErrorList);
						continue;
					}
				} catch (Exception) {

				}

				try {
					if (tmpCaseInsensitiveMap.ContainsKey("Errors[0].Description")) {
						List<Dictionary<String,Object>> tmpErrorList = (List<Dictionary<String,Object>>) tmpCaseInsensitiveMap.Get("Errors");
						AddError(tmpErrorList);
                        continue;
					}
				} catch (Exception) {

				}

				try {

					if (tmpCaseInsensitiveMap.ContainsKey("Description")) {
						AddError(tmpErrorMap);
						continue;
					}
				} catch (Exception) {

				}
        	}
		}


		protected void AddError(List<Dictionary<String,Object>> errors) {
			foreach(Dictionary<String,Object> error in errors) {
				AddError(error);
			}
		}

		protected void AddError(Dictionary<String,Object> error) {
			errors.Add(error);
		}

		protected void ParseFirstErrorToMemberVariables() {
        if (errors.Count > 0) {
            Dictionary<String,Object> tmpErrorMap = errors[0];
            rawErrorData = new SmartMap(tmpErrorMap, true);
            if (rawErrorData.Get("Source") != null) {
                source = rawErrorData.Get("Source").ToString();
            }
            if (rawErrorData.Get("ReasonCode") != null) {
                reasonCode = rawErrorData.Get("ReasonCode").ToString();
            }
            if (rawErrorData.Get("Description") != null) {
                description = rawErrorData.Get("Description").ToString();
            }
        }
    }

		/// <summary>
		/// Returns the API error exception list. </summary>
		/// <returns> a list representing the error data for this exception (which may be a empty list) </returns>
		public virtual List<Dictionary<String,Object>> ListErrors
		{
			get
			{
				return errors;
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
		public virtual int HttpStatus
		{
			get
			{
				return httpStatus;
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