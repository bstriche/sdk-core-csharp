using System;
using RestSharp;


namespace MasterCard.Core.Security
{
	public interface AuthenticationInterface
	{
		void SignRequest(Uri uri, IRestRequest request);
		String SignMessage(String message);
	}
}

