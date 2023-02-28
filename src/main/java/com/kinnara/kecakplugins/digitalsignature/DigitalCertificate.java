package com.kinnara.kecakplugins.digitalsignature;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfWidgetAnnotation;
import com.itextpdf.signatures.*;
import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.mysql.cj.log.Log;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.lib.FileUpload;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.SetupManager;
import org.joget.directory.model.User;
import org.joget.plugin.base.PluginManager;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.json.JSONArray;
import org.json.JSONException;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.stream.Stream;


public class DigitalCertificate extends FileUpload{
    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        if(getLoadBinder() == null) {
            return super.renderTemplate(formData, dataModel);
        }

        String template = "DigitalCertificate.ftl";

        formData = FormUtil.executeLoadBinders(this, formData);
        FormRowSet rowSet = formData.getLoadBinderData(this);

        Map<String, String> filePaths = Optional.ofNullable(rowSet)
                .map(Collection::stream)
                .orElseGet(Stream::empty)
                .map(Hashtable::entrySet)
                .flatMap(Collection::stream)
                .collect(HashMap::new, (m, e) -> m.put(String.valueOf(e.getKey()), String.valueOf(e.getValue())),
                        HashMap::putAll);

        if(!filePaths.isEmpty())
            dataModel.put("filePaths", filePaths);

        return FormUtil.generateElementHtml(this, formData, template, dataModel);
    }

    public FormRowSet formatData(FormData formData) {

        LogUtil.info(getClassName(), "new plugins 4");

        WorkflowUserManager wum = (WorkflowUserManager)AppUtil.getApplicationContext().getBean("workflowUserManager");
        User user = wum.getCurrentUser();
        String username = user.getUsername();
        char[] pass = getPassword();
//        char[] pass = "Kinnara123".toCharArray();

        //get uploaded file from app_temp
        String filePath = FormUtil.getElementPropertyValue(this, formData);
        File fileObj = new File(filePath);
        String absolutePath;

        try {

            if(fileObj.exists()){
                fileObj = FileManager.getFileByPath(filePath);
            }else{
                //update current file
                Form form = FormUtil.findRootForm(this);
                URL fileUrl = ResourceUtils.getURL("wflow/app_formuploads/"+form.getPropertyString(FormUtil.PROPERTY_ID)+"/"+form.getPrimaryKeyValue(formData)+"/"+filePath);
                fileObj = ResourceUtils.getFile(fileUrl.getPath());
            }
            absolutePath = fileObj.getAbsolutePath();

            //get digital certificate of current user login
            URL url = ResourceUtils.getURL("wflow/app_certificate/"+username+".pkcs12");
            File certFile = new File(url.getPath());
            if(!certFile.exists()){
                generateKey(username, pass, user.getFirstName()+" "+user.getLastName());
            }

//            URL url = ResourceUtils.getURL("wflow/app_certificate/kinnarastudio.p12");
            certFile = ResourceUtils.getFile(url);
            String path = certFile.getAbsolutePath();

            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(Files.newInputStream(Paths.get(path)), pass);
            String alias = ks.aliases().nextElement();
            Certificate[] chain = ks.getCertificateChain(alias);

//            KeyPair retrievedKeyPair = loadFromPKCS12(path, pass);
//            PrivateKey privateKey = retrievedKeyPair.getPrivate();
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pass);

            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);

            sign(user.getFirstName()+" "+user.getLastName(), absolutePath, absolutePath , chain, privateKey, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                    "Approval", "Kecak Indonesia", null, null, null, 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        if(getStoreBinder() == null) {
            return super.formatData(formData);
        }

        FormStoreBinder formStoreBinder = FormUtil.findStoreBinder(this);
        return formStoreBinder.store(this, new FormRowSet(), formData);
    }

    public char[] getPassword(){
        SetupManager sm = (SetupManager) SecurityUtil.getApplicationContext().getBean("setupManager");
        String password = sm.getSettingValue("securityKey");
        return (password == null) ? "password123".toCharArray() : password.toCharArray();
    }

    public void generateKey(String username, char[] pass, String name) throws Exception {
        KeyPair generatedKeyPair = generateKeyPair();
        String filename = "wflow/app_certificate/" + username + ".pkcs12";
        storeToPKCS12(filename, pass, generatedKeyPair, name);
        //  KeyPair retrievedKeyPair = loadFromPKCS12(filename, pass);

        // you can validate by generating a signature and verifying it or by
        // comparing the moduli by first casting to RSAPublicKey, e.g.:

        //RSAPublicKey pubKey = (RSAPublicKey) generatedKeyPair.getPublic();
        //RSAPrivateKey privateKey = (RSAPrivateKey) retrievedKeyPair.getPrivate();

    }

    private static KeyPair loadFromPKCS12(String filename, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");

        try (FileInputStream fis = new FileInputStream(filename);) {
            pkcs12KeyStore.load(fis, password);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
        String alias = pkcs12KeyStore.aliases().nextElement();
        KeyStore.Entry entry = pkcs12KeyStore.getEntry(alias, param);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new KeyStoreException("That's not a private key!");
        }
        KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        PublicKey publicKey = privKeyEntry.getCertificate().getPublicKey();
        PrivateKey privateKey = privKeyEntry.getPrivateKey();
        return new KeyPair(publicKey, privateKey);
    }

    public static Certificate selfSign(KeyPair keyPair, String subjectDN)
            throws OperatorCreationException, CertificateException, IOException
    {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(subjectDN);

        // Using the current timestamp as the certificate serial number
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        // 1 Yr validity
        calendar.add(Calendar.YEAR, 1);

        Date endDate = calendar.getTime();

        // Use appropriate signature algorithm based on your keyPair algorithm.
        String signatureAlgorithm = "SHA256WithRSA";

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair
                .getPublic().getEncoded());

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(dnName,
                certSerialNumber, startDate, endDate, dnName, subjectPublicKeyInfo);

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(
                bcProvider).build(keyPair.getPrivate());

        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .getCertificate(certificateHolder);
    }

    private static void storeToPKCS12(
            String filename, char[] password,
            KeyPair generatedKeyPair, String name) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException,
            OperatorCreationException {

        Certificate selfSignedCertificate = selfSign(generatedKeyPair, "CN=" + name);

        KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");
        pkcs12KeyStore.load(null, null);

        KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(generatedKeyPair.getPrivate(),
                new Certificate[] { selfSignedCertificate });
        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
        pkcs12KeyStore.setEntry(name, entry, param);

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            pkcs12KeyStore.store(fos, password);
        }
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());

        return generator.generateKeyPair();
    }

    public void sign(String name, String src, String dest, Certificate[] chain, PrivateKey pk,
                     String digestAlgorithm, String provider, PdfSigner.CryptoStandard subFilter,
                     String reason, String location, Collection<ICrlClient> crlList,
                     IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize) throws IOException, GeneralSecurityException {


        //check if pdf signed with same user. if signed with same user, clear.
        PdfReader testReader = new PdfReader(src);
        clearSameCertificate(testReader, name);

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest, true), new StampingProperties());

        // Create the signature appearance

//        Rectangle rect = new Rectangle(0, 0, 200, 100);
//        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
//
//        appearance
//                .setReason(reason)
//                .setLocation(location)
//
//                // Specify if the appearance before field is signed will be used
//                // as a background for the signed field. The "false" value is the default value.
//                .setReuseAppearance(false)
//                .setPageRect(rect)
//                .setPageNumber(1);
//        signer.setFieldName(name);

        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subFilter);
    }

    public void clearSameCertificate(PdfReader reader, String username)
    {
        PdfDocument pdfDocument = new PdfDocument(reader);
        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
        for (String name : signatureUtil.getSignatureNames()) {
            if(name.compareTo(username) == 0){
                PdfAcroForm acroForm = PdfAcroForm.getAcroForm(pdfDocument, false);
                PdfFormField pdfFormField = acroForm.getField(name);
                if (null != pdfFormField.getPdfObject().remove(PdfName.V))
                    pdfFormField.getPdfObject().setModified();
                for (PdfWidgetAnnotation pdfWidgetAnnotation : pdfFormField.getWidgets()) {
                    if (pdfWidgetAnnotation.getPdfObject().remove(PdfName.AP) != null)
                        pdfWidgetAnnotation.getPdfObject().setModified();
                }
                break;
            }
        }
    }

    @Override
    public String getName() {
        return "Upload DigiCert-able File";
    }

    @Override
    public String getVersion() {
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        ResourceBundle resourceBundle = pluginManager.getPluginMessageBundle(getClassName(), "/message/BuildNumber");
        return resourceBundle.getString("buildNumber");
    }

    @Override
    public String getDescription() {
        return getClass().getPackage().getImplementationTitle();
    }

    @Override
    public String getLabel() {
        return getName();
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getFormBuilderCategory() {
        return "Kecak";
    }

    @Override
    public String getPropertyOptions() {
        try {
            JSONArray currentPluginProperties = new JSONArray(AppUtil.readPluginResource(getClassName(), "/properties/DigitalCertificate.json", null, true, "/messages/DigitalCertificate"));
            JSONArray parentPluginProperties = new JSONArray(super.getPropertyOptions());

            // merge with parent's plugin properties
            for(int i = 0, size = currentPluginProperties.length(); i < size; i++) {
                parentPluginProperties.put(currentPluginProperties.getJSONObject(i));
            }

            return parentPluginProperties.toString().replace("\"", "'");
        } catch (JSONException e) {
            LogUtil.error(getClassName(), e, e.getMessage());
            return super.getPropertyOptions();
        }
    }



}
