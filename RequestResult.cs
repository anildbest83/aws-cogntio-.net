using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Claims;

namespace CognitoApi
{
    public class RequestResult
    {
        public bool Status { get; set; }
        public string Message { get; set; }
        public string Token { get; set; }
        public object Data { get; set; }
        public string Id { get; set; }
        public IEnumerable<Claim> cc { get; set; }
    }
}