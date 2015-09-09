using System;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.Linq;

/// <summary>
/// Derived from Dominick Baier's port available here: 
/// https://github.com/IdentityModel/Thinktecture.IdentityModel.45/blob/48090a5bf24c92f89228469a481156f71b0d859f/IdentityModel/Thinktecture.IdentityModel/WSTrust/WSTrustBindingBase.cs
/// </summary>
public abstract class WSTrust13Binding : Binding
{
    private SecurityMode _securityMode;

    public bool EnableRsaProofKeys { get; set; }

    public override string Scheme
    {
        get
        {
            TransportBindingElement element = this.CreateBindingElements().Find<TransportBindingElement>();

            if (element == null)
            {
                return string.Empty;
            }

            return element.Scheme;
        }
    }

    public SecurityMode SecurityMode
    {
        get
        {
            return this._securityMode;
        }
        set
        {
            ValidateSecurityMode(value);
            this._securityMode = value;
        }
    }

    protected abstract void ApplyTransportSecurity(HttpTransportBindingElement transport);
    protected abstract SecurityBindingElement CreateSecurityBindingElement();

    protected WSTrust13Binding(SecurityMode securityMode)
    {
        this._securityMode = SecurityMode.Message;

        ValidateSecurityMode(securityMode);
        this._securityMode = securityMode;
    }

    protected virtual SecurityBindingElement ApplyMessageSecurity(SecurityBindingElement securityBindingElement)
    {
        if (securityBindingElement == null)
        {
            throw new ArgumentNullException("securityBindingElement");
        }

        securityBindingElement.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;

        if (this.EnableRsaProofKeys)
        {
            RsaSecurityTokenParameters item = new RsaSecurityTokenParameters
            {
                InclusionMode = SecurityTokenInclusionMode.Never,
                RequireDerivedKeys = false
            };
            securityBindingElement.OptionalEndpointSupportingTokenParameters.Endorsing.Add(item);
        }

        return securityBindingElement;
    }

    public override BindingElementCollection CreateBindingElements()
    {
        BindingElementCollection elements = new BindingElementCollection();
        elements.Clear();
        if ((SecurityMode.Message == this._securityMode) || (SecurityMode.TransportWithMessageCredential == this._securityMode))
        {
            elements.Add(this.ApplyMessageSecurity(this.CreateSecurityBindingElement()));
        }
        elements.Add(this.CreateEncodingBindingElement());
        elements.Add(this.CreateTransportBindingElement());
        return elements.Clone();
    }

    protected virtual MessageEncodingBindingElement CreateEncodingBindingElement()
    {
        return new TextMessageEncodingBindingElement { ReaderQuotas = { MaxArrayLength = 0x200000, MaxStringContentLength = 0x200000 } };
    }

    protected virtual HttpTransportBindingElement CreateTransportBindingElement()
    {
        HttpTransportBindingElement element;

        if (SecurityMode.Message == this._securityMode)
        {
            element = new HttpTransportBindingElement();
        }
        else
        {
            element = new HttpsTransportBindingElement();
        }

        element.MaxReceivedMessageSize = Int32.MaxValue;

        if (SecurityMode.Transport == this._securityMode)
        {
            this.ApplyTransportSecurity(element);
        }

        return element;
    }

    protected static void ValidateSecurityMode(SecurityMode securityMode)
    {
        SecurityMode[] allowedModes = { SecurityMode.Message, SecurityMode.Transport, SecurityMode.TransportWithMessageCredential };

        if (!allowedModes.Contains(securityMode))
        {
            throw new ArgumentException();
        }
    }
}