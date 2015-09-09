using System;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Linq;

/// <summary>
/// Derived from Dominick Baier's port available here: 
/// https://github.com/IdentityModel/Thinktecture.IdentityModel.45/blob/48090a5bf24c92f89228469a481156f71b0d859f/IdentityModel/Thinktecture.IdentityModel/WSTrust/UserNameWSTrustBinding.cs
/// </summary>
public class UserNameWSTrustBinding : WSTrust13Binding
{
    private HttpClientCredentialType _clientCredentialType;

    public HttpClientCredentialType ClientCredentialType
    {
        get
        {
            return this._clientCredentialType;
        }
        set
        {
            if (!IsHttpClientCredentialTypeDefined(value))
            {
                throw new ArgumentException();
            }
            if (!IsValidForTransportSecurity(value))
            {
                throw new ArgumentException("Transport Security Requires either Digest or Basic Client Credentials.");
            }
            this._clientCredentialType = value;
        }
    }

    public UserNameWSTrustBinding()
        : this(SecurityMode.TransportWithMessageCredential, HttpClientCredentialType.None)
    { }

    public UserNameWSTrustBinding(SecurityMode mode, HttpClientCredentialType clientCredentialType)
        : base(mode)
    {
        this.ClientCredentialType = clientCredentialType;
    }

    protected override void ApplyTransportSecurity(HttpTransportBindingElement transport)
    {
        if (this._clientCredentialType == HttpClientCredentialType.Basic)
        {
            transport.AuthenticationScheme = AuthenticationSchemes.Basic;
        }
        else
        {
            transport.AuthenticationScheme = AuthenticationSchemes.Digest;
        }
    }

    protected override SecurityBindingElement CreateSecurityBindingElement()
    {
        SecurityBindingElement securityElement = null;

        if (SecurityMode.Message == base.SecurityMode)
        {
            securityElement = SecurityBindingElement.CreateUserNameForCertificateBindingElement();
        }
        else if (SecurityMode.TransportWithMessageCredential == base.SecurityMode)
        {
            securityElement = SecurityBindingElement.CreateUserNameOverTransportBindingElement();
        }

        return securityElement;
    }

    private bool IsHttpClientCredentialTypeDefined(HttpClientCredentialType value)
    {
        HttpClientCredentialType[] knownTypes = { HttpClientCredentialType.None, HttpClientCredentialType.Basic, HttpClientCredentialType.Digest, HttpClientCredentialType.Ntlm, HttpClientCredentialType.Windows, HttpClientCredentialType.Certificate };

        return knownTypes.Contains(value);
    }

    private bool IsValidForTransportSecurity(HttpClientCredentialType value)
    {
        HttpClientCredentialType[] allowedTypesForTransport = { HttpClientCredentialType.Digest, HttpClientCredentialType.Basic };

        if (SecurityMode.Transport == base.SecurityMode)
        {
            return !allowedTypesForTransport.Contains(value);
        }
        else
        {
            return true;
        }
    }

}