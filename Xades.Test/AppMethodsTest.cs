using IPS.Signature.Xades;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Xades.Test
{
    [TestClass]
    public class AppMethodsTest
    {
        internal static X509Certificate2 LetsFindACertificate()
        {
            var filename = AppDomain.CurrentDomain.BaseDirectory + "self-signed-ips.pfx_for_test";
            return new X509Certificate2(filename, "1234567890", X509KeyStorageFlags.Exportable);
        }

        [TestMethod]
        public void Test()
        {
            var cert = LetsFindACertificate();
            var signedXml = IPSSignedXml.SignDataPDU(XmlMessages.msg_2_sign, cert);
            Assert.IsTrue(signedXml.Contains("QualifyingProperties"));

            Console.WriteLine(signedXml);

            IPSSignedXml.VerifySignature(signedXml, cert, true);
        }
    }
}
