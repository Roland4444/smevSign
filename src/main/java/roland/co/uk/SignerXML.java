package roland.co.uk;

import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import static com.sun.xml.internal.ws.spi.db.BindingContextFactory.LOGGER;

public class SignerXML {
    private static final String XMLDSIG_MORE_GOSTR34102001_GOSTR3411 = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
    private static final String XMLDSIG_MORE_GOSTR3411 = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    private static final String CANONICALIZATION_METHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String DS_SIGNATURE = "//ds:Signature";
    private static final String SIG_ID = "sigID";
    private static final String COULD_NOT_FIND_XML_ELEMENT_NAME = "ERROR! Could not find xmlElementName = ";
    private static final String GRID = "#";
    private static final String XML_SIGNATURE_ERROR = "xmlDSignature ERROR: ";
    public SignerXML() throws InvalidTransformException, AlgorithmAlreadyRegisteredException, ClassNotFoundException, SignatureProcessorException {
        ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit.init();
        Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getName());
        santuarioIgnoreLineBreaks(true);
    }
    public static void main(String[] args){
        System.out.print("init JCP");
    }

    private static final String IGNORE_LINE_BREAKS_FIELD = "ignoreLineBreaks";

    private void santuarioIgnoreLineBreaks(Boolean mode) {
        try {
            Boolean currMode = mode;
            AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                public Boolean run() throws Exception {
                    Field f = XMLUtils.class.getDeclaredField(IGNORE_LINE_BREAKS_FIELD);
                    f.setAccessible(true);
                    f.set(null, currMode);
                    return false;
                }
            });
        } catch (Exception e) {
            LOGGER.warning("santuarioIgnoreLineBreaks " );
        }
    }

    public byte[] sign(byte[] data) throws ParserConfigurationException, IOException, SAXException, XMLSecurityException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException, TransformerException {
        String xmlElementName="ns2:CallerInformationSystemSignature";
        String xmlElementID="SIGNED_BY_CONSUMER";
        Sign x = new Sign();
        X509Certificate certificate=(X509Certificate)x.getCert();
        PrivateKey privateKey=x.getPrivate();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setCoalescing(true);
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(data));
        final String signMethod = XMLDSIG_MORE_GOSTR34102001_GOSTR3411;
        final String digestMethod = XMLDSIG_MORE_GOSTR3411;
        final String canonicalizationMethod = CANONICALIZATION_METHOD;
        String sigId = SIG_ID;
        XMLSignature sig = new XMLSignature(doc, "", signMethod, canonicalizationMethod);
        sig.setId(sigId);
        Element anElement = null;
        if (xmlElementName == null)
            anElement = doc.getDocumentElement();
        else {
            NodeList nodeList = doc.getElementsByTagName(xmlElementName);
            anElement = (Element) nodeList.item(0);
        }
        if (anElement != null)
            anElement.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);
        sig.addDocument(xmlElementID == null ? "" : GRID + xmlElementID, transforms, digestMethod);
        sig.addKeyInfo(certificate);
        sig.sign(privateKey);
        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(bais));
        bais.close();
        return bais.toByteArray();
    }
}
