using Shouldly;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace IPS.Signature.Xades
{
    public class IPSSignedXml : SignedXml
    {
        /// <summary>
        /// The XAdES XML namespace URI
        /// </summary>
        public const string XadesNamespaceUri = "http://uri.etsi.org/01903/v1.3.2#";

        /// <summary>
        /// Mandated type name for the Uri reference to the SignedProperties element
        /// </summary>
        public const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903/v1.3.2#SignedProperties";

        public IPSSignedXml(XmlDocument d) : base(d) { }

        public static string NewId => $"_{Guid.NewGuid()}";

        public static XmlDocument GetAsXmlDocument(XmlNode x)
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(x.OuterXml);
            return doc;
        }

        public static XmlDocument GetAsXmlDocument(string xml)
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(xml);
            return doc;
        }

        public static XmlElement GetFirstOfXmlElementsByTag(XmlElement e, string tag, string ns = null)
        {
            var res = GetFirstOfXmlElementsByTagOrNull(e, tag, ns);
            if (res == null)
                throw new InvalidOperationException($"Tag '{tag}' in ns '{ns}' isn't found.");
            return res;
        }

        public static XmlElement GetFirstOfXmlElementsByTagOrNull(XmlElement e, string tag, string ns = null)
        {
            e.ShouldNotBeNull();
            XmlNodeList nodeList = null;
            if (ns == null)
                nodeList = e.GetElementsByTagName(tag);
            else
                nodeList = e.GetElementsByTagName(tag, ns);
            if ((nodeList?.Count ?? 0) < 1)
                return null;
            return (XmlElement)nodeList[0];
        }

        static Reference CreateReferenceHack(XmlElement e)
        {
            var ctr = typeof(Reference).GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(XmlElement) }, null);
            if (ctr == null)
                throw new Exception("Reference ctor err");
            var s = new Reference();
            ctr.Invoke(s, new object[] { e });
            return s;
        }

        public static bool CheckCert(X509Certificate2 certificate)
        {
            certificate.ShouldNotBeNull("Certificate must be not null");

            // check the certificate
            var Chain = new X509Chain();
            Chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            Chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);
            Chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            return Chain.Build(certificate);
        }

        public static string Serialize(object o, bool omitxml = true)
        {
            var serializedValue = string.Empty;
            var settings = new XmlWriterSettings
            {
                Indent = true,
                IndentChars = "\t",
                OmitXmlDeclaration = omitxml,
                Encoding = new UTF8Encoding(false),
                NamespaceHandling = NamespaceHandling.OmitDuplicates
            };

            var nsm = new XmlSerializerNamespaces();
            nsm.Add("ds", XmlDsigNamespaceUrl);
            nsm.Add("xades", XadesNamespaceUri);

            using (var output = new MemoryStream())
            using (var writer = XmlWriter.Create(output, settings))
            {
                var x = new XmlSerializer(o.GetType());
                x.Serialize(writer, o, nsm);
                serializedValue = Encoding.Default.GetString(output.ToArray());
            }
            return serializedValue.ToString();
        }

        public static string Beautify(string xml)
        {
            return XDocument.Parse(xml).ToString();
        }

        public static string SignDataPDU(string datapduxml, X509Certificate2 certificate)
        {
            datapduxml = Beautify(datapduxml);

            var datapdu = GetAsXmlDocument(datapduxml);
            datapdu.DocumentElement?.Name.ShouldBe("DataPDU", "XML must contain DataPDU node");
            var sgntr = GetFirstOfXmlElementsByTagOrNull(datapdu.DocumentElement, "Sgntr");
            sgntr.ShouldNotBeNull("XML must contain AppHdr.Sgntr node");
            var doc = GetFirstOfXmlElementsByTagOrNull(datapdu.DocumentElement, "Document");
            doc.ShouldNotBeNull("XML must contain Document node");
            certificate.ShouldNotBeNull("Certificate must be not null");

            // first pass - create signature without references and add it to the document to sign
            var rsaKey = certificate.GetRSAPrivateKey();

            var xadesSignedXml = new IPSSignedXml(GetAsXmlDocument(datapdu)) { SigningKey = rsaKey };

            // keyinfo
            var keyInfo = new KeyInfo { Id = NewId };
            var kidata = new KeyInfoX509Data();
            kidata.AddIssuerSerial(certificate.Issuer, certificate.SerialNumber);
            keyInfo.AddClause(kidata);

            xadesSignedXml.KeyInfo = keyInfo;

            // signedinfo with references
            xadesSignedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            xadesSignedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

            // xades obj
            var props = new QualifyingPropertiesType { SignedProperties = new SignedPropertiesType { Id = NewId + "-signedprops" } };//, Target = "#1" };
            var ssp = props.SignedProperties.SignedSignatureProperties = new SignedSignaturePropertiesType();
            ssp.SigningTime = DateTime.Now; //ISO 8601 format as required in http://www.w3.org/TR/xmlschema-2/#dateTime  } }
            ssp.SigningTimeSpecified = true;
            var qp = Serialize(props);
            var qpdoc = GetAsXmlDocument(qp);

            var dataObject = new DataObject();
            dataObject.Data = qpdoc.ChildNodes;
            xadesSignedXml.AddObject(dataObject);

            // to sign the whole xml document, not Document node
            var reference0 = new Reference("") { DigestMethod = SignedXml.XmlDsigSHA256Url };
            reference0.AddTransform(new XmlDsigExcC14NTransform());
            xadesSignedXml.AddReference(reference0);

            xadesSignedXml.ComputeSignature();
            var signature1 = xadesSignedXml.GetXml();

            sgntr.AppendChild(datapdu.ImportNode(signature1, true));

            Debug.WriteLine("1st_pass.xml:\r\n" + Beautify(datapdu.OuterXml));


            // second pass - create real signatures over the real document
            var xadesSignedXml2 = new IPSSignedXml(GetAsXmlDocument(datapdu)) { SigningKey = rsaKey };
            xadesSignedXml2.LoadXml(signature1);

            xadesSignedXml2.SignedInfo.References.Clear();
            //to sign the key
            var reference = new Reference("#" + xadesSignedXml.KeyInfo.Id) { DigestMethod = SignedXml.XmlDsigSHA256Url };
            reference.AddTransform(new XmlDsigExcC14NTransform());
            xadesSignedXml2.AddReference(reference);

            var reference2 = new Reference("#" + props.SignedProperties.Id) { DigestMethod = SignedXml.XmlDsigSHA256Url };
            reference2.Type = SignedPropertiesTypeUri;
            reference2.AddTransform(new XmlDsigExcC14NTransform());
            xadesSignedXml2.AddReference(reference2); //Add the XAdES object reference

            //to sign the Document node
            var reference3 = CreateReferenceHack(doc);
            reference3.Uri = "";
            reference3.DigestMethod = SignedXml.XmlDsigSHA256Url;
            reference3.AddTransform(new XmlDsigExcC14NTransform());
            xadesSignedXml2.AddReference(reference3);

            xadesSignedXml2.ComputeSignature();
            var signature2 = xadesSignedXml2.GetXml();

            sgntr.RemoveAll();
            sgntr.AppendChild(datapdu.ImportNode(signature2, true));

            Debug.WriteLine("2nd_pass.xml:\r\n" + datapdu.OuterXml);

            return datapdu.OuterXml;
        }

        public static void VerifySignature(string signedxml, X509Certificate2 certificate, bool signatureonly = false)
        {
            var datapdu = GetAsXmlDocument(signedxml);
            datapdu.DocumentElement?.Name.ShouldBe("DataPDU", "XML must contain DataPDU node");
            var sgntr = GetFirstOfXmlElementsByTagOrNull(datapdu.DocumentElement, "Sgntr");
            sgntr.ShouldNotBeNull("XML must contain AppHdr.Sgntr node");
            var doc = GetFirstOfXmlElementsByTagOrNull(datapdu.DocumentElement, "Document");
            doc.ShouldNotBeNull("XML must contain Document node");

            var rsaKey = certificate.GetRSAPrivateKey();
            var signedXml = new IPSSignedXml(GetAsXmlDocument(datapdu)) { SigningKey = rsaKey };
            signedXml.LoadXml((XmlElement)sgntr.FirstChild);

            signedXml.SignedInfo.References.Count.ShouldBe(3, "Wrong number SignedInfo.References");
            var oldref = (Reference)signedXml.SignedInfo.References[2];
            signedXml.SignedInfo.References.RemoveAt(2);

            var reference3 = CreateReferenceHack(doc);
            reference3.DigestValue = oldref.DigestValue;
            reference3.Uri = "";
            reference3.DigestMethod = SignedXml.XmlDsigSHA256Url;
            reference3.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference3);

            if (!signedXml.CheckSignature(certificate, signatureonly))
                throw new InvalidOperationException("Signature is invalid.");
        }
    }
}
