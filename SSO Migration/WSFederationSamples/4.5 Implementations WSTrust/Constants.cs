using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class Constants
{
    public class TokenTypes
    {
        public const string SAML1 = @"urn:oasis:names:tc:SAML:1.0:assertion";
        public const string SAML2 = @"urn:oasis:names:tc:SAML:2.0:assertion";
        public const string JWT = @"urn:ietf:params:oauth:token-type:jwt";
        public const string SWT = @"http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0";
    }
    
}
