﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Xades.Test {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "17.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class XmlMessages {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal XmlMessages() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Xades.Test.XmlMessages", typeof(XmlMessages).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
        ///&lt;DataPDU xmlns=&quot;urn:cma:stp:xsd:stp.1.0&quot;&gt;
        ///   &lt;Body&gt;
        ///      &lt;AppHdr xmlns=&quot;urn:iso:std:iso:20022:tech:xsd:head.001.001.01&quot;&gt;
        ///         &lt;Fr&gt;
        ///            &lt;FIId&gt;
        ///               &lt;FinInstnId&gt;
        ///                  &lt;BICFI&gt;AAAAYYZZ&lt;/BICFI&gt;
        ///               &lt;/FinInstnId&gt;
        ///            &lt;/FIId&gt;
        ///         &lt;/Fr&gt;
        ///         &lt;To&gt;
        ///            &lt;FIId&gt;
        ///               &lt;FinInstnId&gt;
        ///                  &lt;BICFI&gt;SYSTEMZZ&lt;/BICFI&gt;
        ///               &lt;/FinInstnId&gt;
        ///            &lt;/FIId&gt;
        ///         &lt;/To&gt;        /// [rest of string was truncated]&quot;;.
        /// </summary>
        internal static string msg_2_sign {
            get {
                return ResourceManager.GetString("msg_2_sign", resourceCulture);
            }
        }
    }
}
