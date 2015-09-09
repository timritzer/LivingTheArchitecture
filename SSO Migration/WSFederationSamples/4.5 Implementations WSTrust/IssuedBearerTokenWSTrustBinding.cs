using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Xml;

/// <summary>
/// Derived from Dominick Baier's port available here: 
/// https://github.com/IdentityModel/Thinktecture.IdentityModel.45/blob/48090a5bf24c92f89228469a481156f71b0d859f/IdentityModel/Thinktecture.IdentityModel/WSTrust/IssuedTokenWSTrustBinding.cs
/// </summary>
public class IssuedBearerTokenWSTrustBinding : WSTrust13Binding
{

    public SecurityAlgorithmSuite AlgorithmSuite { get; set; }

    public Collection<ClaimTypeRequirement> ClaimTypeRequirements { get; private set; }

    public EndpointAddress IssuerAddress { get; set; }

    public Binding IssuerBinding { get; set; }

    public EndpointAddress IssuerMetadataAddress { get; set; }

    public SecurityKeyType KeyType { get; set; }

    public string TokenType { get; set; }


    public IssuedBearerTokenWSTrustBinding()
        : this(null, null, SecurityMode.TransportWithMessageCredential, SecurityAlgorithmSuite.Basic256, null, null, null)
    { }

    public IssuedBearerTokenWSTrustBinding(Binding issuerBinding, EndpointAddress issuerAddress, SecurityMode mode, SecurityAlgorithmSuite algorithmSuite, string tokenType, IEnumerable<ClaimTypeRequirement> claimTypeRequirements, EndpointAddress issuerMetadataAddress)
        : base(mode)
    {
        this.ClaimTypeRequirements = new Collection<ClaimTypeRequirement>();

        if ((SecurityMode.Message != mode) && (SecurityMode.TransportWithMessageCredential != mode))
        {
            throw new ArgumentException("Security Mode must be TransportWithMessageCredential or Message");
        }

        this.KeyType = SecurityKeyType.BearerKey;
        this.AlgorithmSuite = algorithmSuite;
        this.TokenType = tokenType;
        this.IssuerBinding = issuerBinding;
        this.IssuerAddress = issuerAddress;
        this.IssuerMetadataAddress = issuerMetadataAddress;

        if (claimTypeRequirements != null)
        {
            foreach (ClaimTypeRequirement requirement in claimTypeRequirements)
            {
                this.ClaimTypeRequirements.Add(requirement);
            }
        }
    }

    private void AddAlgorithmParameters(SecurityAlgorithmSuite algorithmSuite, ref IssuedSecurityTokenParameters issuedParameters)
    {
        issuedParameters.AdditionalRequestParameters.Insert(0, this.CreateEncryptionAlgorithmElement(algorithmSuite.DefaultEncryptionAlgorithm));
        issuedParameters.AdditionalRequestParameters.Insert(0, this.CreateCanonicalizationAlgorithmElement(algorithmSuite.DefaultCanonicalizationAlgorithm));
    }

    protected override void ApplyTransportSecurity(HttpTransportBindingElement transport)
    {
        throw new NotSupportedException();
    }

    private XmlElement CreateCanonicalizationAlgorithmElement(string canonicalizationAlgorithm)
    {
        if (canonicalizationAlgorithm == null)
        {
            throw new ArgumentNullException("canonicalizationAlgorithm");
        }

        var document = new XmlDocument();
        XmlElement element = null;

        element = document.CreateElement("trust", "CanonicalizationAlgorithm", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");

        if (element != null)
        {
            element.AppendChild(document.CreateTextNode(canonicalizationAlgorithm));
        }

        return element;
    }

    private XmlElement CreateEncryptionAlgorithmElement(string encryptionAlgorithm)
    {
        if (encryptionAlgorithm == null)
        {
            throw new ArgumentNullException("encryptionAlgorithm");
        }

        XmlDocument document = new XmlDocument();
        XmlElement element = null;

        element = document.CreateElement("trust", "EncryptionAlgorithm", "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
        
        if (element != null)
        {
            element.AppendChild(document.CreateTextNode(encryptionAlgorithm));
        }

        return element;
    }

    protected override SecurityBindingElement CreateSecurityBindingElement()
    {
        SecurityBindingElement element;

        IssuedSecurityTokenParameters issuedParameters = new IssuedSecurityTokenParameters(this.TokenType, this.IssuerAddress, this.IssuerBinding)
        {
            KeyType = this.KeyType,
            IssuerMetadataAddress = this.IssuerMetadataAddress
        };

            issuedParameters.KeySize = 0;

        if (this.ClaimTypeRequirements != null)
        {
            foreach (ClaimTypeRequirement requirement in this.ClaimTypeRequirements)
            {
                issuedParameters.ClaimTypeRequirements.Add(requirement);
            }
        }

        this.AddAlgorithmParameters(this.AlgorithmSuite, ref issuedParameters);
        if (SecurityMode.Message == base.SecurityMode)
        {
            element = SecurityBindingElement.CreateIssuedTokenForCertificateBindingElement(issuedParameters);
        }
        else
        {
            element = SecurityBindingElement.CreateIssuedTokenOverTransportBindingElement(issuedParameters);
        }

        element.DefaultAlgorithmSuite = this.AlgorithmSuite;
        element.IncludeTimestamp = true;

        return element;
    }
}