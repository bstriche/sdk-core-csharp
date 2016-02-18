using System;
using RestSharp;


namespace MasterCard.Core.Security
{
	public interface AuthenticationInterface
	{

		void sign(Uri uri, IRestRequest request);

	}
}

