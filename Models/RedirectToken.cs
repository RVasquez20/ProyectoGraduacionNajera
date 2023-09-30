using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplication1.Models
{
    public class RedirectToken
    {
        public string clientId { get; set; }
        public string scope { get; set; }
        public string state { get; set; }
        public string redirectUri { get; set; }
        public string clientSecret { get; set; }
    }
}