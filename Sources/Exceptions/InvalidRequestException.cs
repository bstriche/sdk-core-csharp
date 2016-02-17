using System;
using System.Collections.Generic;
using System.Text;

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
	/// Thrown to indicate that an error occured processing an API request. </summary>
	/// <seealso cref=  String,Objectexception.ApiException </seealso>
	public class InvalidRequestException : ApiException
	{



		protected IList<FieldError> fieldErrors = new List<FieldError>();

		/// <summary>
		///  Constructs an <code>InvalidRequestException</code> with no detail message.
		/// </summary>
		public InvalidRequestException() : base()
		{
		}

		/// <summary>
		///  Constructs an <code>InvalidRequestException</code> with the specified detail message. </summary>
		///  <param name="s"> the detail message. </param>
		public InvalidRequestException(string s) : base(s)
		{
		}

		/// <summary>
		///  Constructs an <code>InvalidRequestException</code> with the specified detail message
		///  and cause. </summary>
		///  <param name="s"> the detail message. </param>
		///  <param name="cause"> the detail message. </param>
		public InvalidRequestException(string s, Exception cause) : base(s, cause)
		{
		}

		/// <summary>
		///  Constructs an <code>InvalidRequestException</code> with the specified cause. </summary>
		///  <param name="cause"> the detail message. </param>
		public InvalidRequestException(Exception cause) : base(cause)
		{
		}

		/// <summary>
		///  Constructs an <code>InvalidRequestException</code> with the specified status
		///  and error data. </summary>
		///  <param name="status"> the HTTP status code </param>
		///  <param name="errorData"> a map representing the error details returned by the API.  The map is
		///                   expected to contain <code>String</code> value for the key  <code>"reference"</code> and
		///                   a map containing the detailed error data for the key <code>"key"</code>.  This map in turn
		///                   is expected to contain <code>String</code> values for the keys
		///                   <code>"code"</code> and <code>"message"</code> and a list for the key <code>"fieldErrors"</code>
		///                   with each entry  containing error information for a particular field. </param>
		/// <seealso cref=  String,Objectexception.ApiException </seealso>
		/// <seealso cref=  String,Objectexception.InvalidRequestException$FieldError </seealso>
		public InvalidRequestException(int status, IDictionary<String,Object> errorData) : base(status, errorData)		{

//			Dictionary<String, Object>  error = (Dictionary<String, Object>) errorData["error"];
//			if (error != null)
//			{
//
//				IList<IDictionary<String, Object>> errors = (IList<IDictionary<String, Object>>) error["fieldErrors"];
//				if (errors != null)
//				{
//					foreach (IDictionary<String, Object> fieldData in errors)
//					{
//						FieldError fe = new FieldError(this, fieldData);
//						fieldErrors.Add(fe);
//					}
//				}
//			}
		}

		/// <summary>
		/// Returns a boolean indicating if this exception contains field errors. </summary>
		/// <returns> a boolean indicating if this exception contains field errors. </returns>
		public virtual bool hasFieldErrors()
		{
			return fieldErrors.Count > 0;
		}

		/// <summary>
		/// Returns the list of field errors for this exception. </summary>
		/// <returns> a list of <code>FieldError</code> objects (may be empty). </returns>
		/// <seealso cref=  String,Objectexception.InvalidRequestException$FieldError </seealso>
		public virtual IList<FieldError> FieldErrors
		{
			get
			{
				return fieldErrors;
			}
		}

		/// <summary>
		/// Returns a string describing the exception. </summary>
		/// <returns> a string describing the exception. </returns>
		public override string describe()
		{
			StringBuilder sb = new StringBuilder(base.describe());
			foreach (FieldError fieldError in FieldErrors)
			{
				sb.Append("\n").Append(fieldError.ToString());
			}
			sb.Append("\n");
			return sb.ToString();
		}






	}

	/// <summary>
	/// Class representing a single error on a field in a request sent to the API.
	/// </summary>
	public class FieldError
	{

		internal string errorCode;
		internal string fieldName;
		internal string message;

		/// <summary>
		/// Constructs a <code>FieldError</code> object using the specified data. </summary>
		/// <param name="data"> a map containing <code>String</code> values for the keys <code>"code"</code>,
		///             <code>"field"</code> and <code>"message"</code>. </param>
		internal FieldError(InvalidRequestException outerInstance, IDictionary<String,Object> data)
		{
			errorCode = (string) data["code"];
			fieldName = (string) data["field"];
			message = (string) data["message"];
		}

		/// <summary>
		/// Returns the error code for this field error. </summary>
		/// <returns> a string error code (may be null). </returns>
		public virtual string ErrorCode
		{
			get
			{
				return errorCode;
			}
		}

		/// <summary>
		/// Returns the field name for this field error. </summary>
		/// <returns> a string field name (may be null). </returns>
		public virtual string FieldName
		{
			get
			{
				return fieldName;
			}
		}

		/// <summary>
		/// Returns the erorr message for this field error. </summary>
		/// <returns> a string error message (may be null). </returns>
		public virtual string Message
		{
			get
			{
				return message;
			}
		}

		public override string ToString()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append("Field error: ").Append(FieldName).Append("\" ").Append(Message).Append("\" (").Append(ErrorCode).Append(")");
			return sb.ToString();
		}
	}



}