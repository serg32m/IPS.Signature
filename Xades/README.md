# Introduction 
The package to sign and check signature of type XAdES-BES in IPS Moldova 
Examples are in the test project

# Details about implementation
1. XSD schemas used to generate XAdES-specific classes for data object (xsd.exe used)
2. Input for both signing and checking is xml string of DataPDU envelop with DataPDU/AppHdr/Sgntr empty node present
3. The first pass of signing creates wittingly wrong signature and adds it to the initial DataPDU to recreate a requested structure
4. The second pass adds 3 references as it required by XAdES (to KeyInfo, to XAdES data object, to payload node), refreshes the signature and adds it again to initial DataPDU
5. Note that reference #3 is created in unusual way
6. Verification requires the certicicate since it is not present in the message as IPS demands
7. Verification can verify only the signature or both the certificate and the signature

# Release notes
1.0.0.0 Initial checkin