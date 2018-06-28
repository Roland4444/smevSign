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
        // установка флага, определяющего игнорирование пробелов в
        // содержимом элементов при обработке XML-документа
        dbf.setIgnoringElementContentWhitespace(true);
        // установка флага, определяющего преобразование узлов CDATA в
        // текстовые узлы при обработке XML-документа
        dbf.setCoalescing(true);
        // установка флага, определяющего поддержку пространств имен при
        // обработке XML-документа
        dbf.setNamespaceAware(true);
// загрузка содержимого подписываемого документа на основе
        // установленных флагами правил из массива байтов data            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(data));
        /*
         * Добавление узла подписи <ds:Signature> в загруженный XML-документ
         */
        // алгоритм подписи (ГОСТ Р 34.10-2001)
        final String signMethod = XMLDSIG_MORE_GOSTR34102001_GOSTR3411;
        // алгоритм хеширования, используемый при подписи (ГОСТ Р 34.11-94)
        final String digestMethod = XMLDSIG_MORE_GOSTR3411;
        final String canonicalizationMethod = CANONICALIZATION_METHOD;
        String[][] filters = {{XPath2FilterContainer.SUBTRACT, DS_SIGNATURE}};
        String sigId = SIG_ID;
        // инициализация объекта формирования ЭЦП в соответствии с
        // алгоритмом ГОСТ Р 34.10-2001
        XMLSignature sig = new XMLSignature(doc, "", signMethod, canonicalizationMethod);
        // определение идентификатора первого узла подписи
        sig.setId(sigId);
        // получение корневого узла XML-документа
        Element anElement = null;
        if (xmlElementName == null) {
            anElement = doc.getDocumentElement();
        } else {
            NodeList nodeList = doc.getElementsByTagName(xmlElementName);
            anElement = (Element) nodeList.item(0);
        }
        // = doc.getElementById("#AppData");
        // добавление в корневой узел XML-документа узла подписи
        if (anElement != null) {
            anElement.appendChild(sig.getElement());
        } else {
           // throw new SignatureProcessorException(COULD_NOT_FIND_XML_ELEMENT_NAME + xmlElementName);
        }
        /*
         * Определение правил работы с XML-документом и добавление в узел подписи этих
         * правил
         */
        // создание узла преобразований <ds:Transforms> обрабатываемого
        // XML-документа
        Transforms transforms = new Transforms(doc);
        // добавление в узел преобразований правил работы с документом
        // transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);
        // добавление в узел подписи ссылок (узла <ds:Reference>),
        // определяющих правила работы с
        // XML-документом (обрабатывается текущий документ с заданными в
        // узле <ds:Transforms> правилами
        // и заданным алгоритмом хеширования)
        sig.addDocument(xmlElementID == null ? "" : GRID + xmlElementID, transforms, digestMethod);
        /*
         * Создание подписи всего содержимого XML-документа на основе закрытого ключа,
         * заданных правил и алгоритмов
         */

        // создание внутри узла подписи узла <ds:KeyInfo> информации об
        // открытом ключе на основе
        // сертификата
        sig.addKeyInfo(certificate);
        // создание подписи XML-документа
        sig.sign(privateKey);
        // определение потока, в который осуществляется запись подписанного
        // XML-документа
        ByteArrayOutputStream bais = new ByteArrayOutputStream();
        // инициализация объекта копирования содержимого XML-документа в
        // поток
        TransformerFactory tf = TransformerFactory.newInstance();
        // создание объекта копирования содержимого XML-документа в поток
        Transformer trans = tf.newTransformer();
        // копирование содержимого XML-документа в поток
        trans.transform(new DOMSource(doc), new StreamResult(bais));
        bais.close();
        return bais.toByteArray();
    }
}
