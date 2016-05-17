using System;
using System.Collections.Generic;

namespace MasterCard.Core.Security
{
	public interface CryptographyInterceptor
	{
		String GetTriggeringPath();
		Dictionary<String,Object> Encrypt(IDictionary<String,Object> map);
		Dictionary<String,Object> Decrypt(IDictionary<String,Object> map);
	}
}

