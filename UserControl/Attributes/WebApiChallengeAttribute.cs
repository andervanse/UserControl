using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.AspNetCore.Mvc.Filters;

namespace UserControl
{
	public class WebApiChallengeAttribute : ActionFilterAttribute
	{
		public override void OnResultExecuted(ResultExecutedContext context)
		{
			context.HttpContext.Response.ContentType = "application/json";
			string jsonResponse = "";

			if (context.HttpContext.Response.Headers.ContainsKey("Location"))
			{
				string responseBody = context.HttpContext.Response.Headers["Location"];

                Debug.WriteLine("Cookie:" + context.HttpContext.Response.Cookies);

				if (!String.IsNullOrEmpty(responseBody))
				{
					context.HttpContext.Response.StatusCode = 200;
					jsonResponse = "{ \"redirectTo\": \"" + responseBody + "\" }";
				}
				else
				{
					context.HttpContext.Response.StatusCode = 400;
					jsonResponse = "{ \"message\": \"400 - not found\" }";
				}
			}
			else
			{
				context.HttpContext.Response.StatusCode = 400;
				jsonResponse = "{ \"message\": \"400 - not found\" }";
			}

			byte[] bytes = Encoding.UTF8.GetBytes(jsonResponse);

			using (MemoryStream mms = new MemoryStream(bytes))
			{
				mms.CopyTo(context.HttpContext.Response.Body);
				Debug.WriteLine(jsonResponse);
			}
		}
	}
}
