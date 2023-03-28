package com.kinnara.kecakplugins.digitalsignature;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnarastudio.commons.Try;
import com.kinnarastudio.commons.jsonstream.JSONStream;
import com.mysql.cj.log.Log;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
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
import org.joget.directory.model.Department;
import org.joget.directory.model.Employment;
import org.joget.directory.model.Organization;
import org.joget.directory.model.User;
import org.joget.directory.model.service.ExtDirectoryManager;
import org.joget.plugin.base.PluginManager;
import org.joget.workflow.util.WorkflowUtil;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Stream;


public class DigitalCertificateFileUpload extends FileUpload {
    public final static String DEFAULT_PASSWORD = "SuperSecurePasswordNoOneCanBreak";
    public final static String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    public final static String PATH_CERTIFICATE = "wflow/app_certificate/";
    public final static String PATH_FORMUPLOADS = "wflow/app_formuploads/";
    public final static String ROOT_CERTIFICATE = "admin.pkcs12";
    public final static String KEYSTORE_TYPE = "pkcs12";
//
//    @Override
//    public String renderTemplate(FormData formData, Map dataModel) {
//        if (getLoadBinder() == null) {
//            return super.renderTemplate(formData, dataModel);
//        }
//
//        String template = "DigitalCertificate.ftl";
//
//        formData = FormUtil.executeLoadBinders(this, formData);
//        FormRowSet rowSet = formData.getLoadBinderData(this);
//
//        Map<String, String> filePaths = Optional.ofNullable(rowSet)
//                .map(Collection::stream)
//                .orElseGet(Stream::empty)
//                .map(Hashtable::entrySet)
//                .flatMap(Collection::stream)
//                .collect(HashMap::new, (m, e) -> m.put(String.valueOf(e.getKey()), String.valueOf(e.getValue())),
//                        HashMap::putAll);
//
//        if (!filePaths.isEmpty())
//            dataModel.put("filePaths", filePaths);
//
//        return FormUtil.generateElementHtml(this, formData, template, dataModel);
//    }

    public FormRowSet formatData(FormData formData) {
        String name = WorkflowUtil.getCurrentUserFullName();
        //get uploaded file from app_temp
        String filePath = FormUtil.getElementPropertyValue(this, formData);
        File fileObj = new File(FileManager.getBaseDirectory() + "/" + filePath);

        try {
            if (fileObj.exists()) {
                fileObj = FileManager.getFileByPath(filePath);
            } else {
                //update current file
                Form form = FormUtil.findRootForm(this);
                URL fileUrl = ResourceUtils.getURL(PATH_FORMUPLOADS + form.getPropertyString(FormUtil.PROPERTY_ID) + "/" + form.getPrimaryKeyValue(formData) + "/" + filePath);
                fileObj = ResourceUtils.getFile(fileUrl.getPath());
            }
            String absolutePath = fileObj.getAbsolutePath();
            boolean signed = isSigned(absolutePath, name);

            if (!signed) {
                //get digital certificate of current user login
                String username = WorkflowUtil.getCurrentUsername();
                URL url = ResourceUtils.getURL(PATH_CERTIFICATE + username + "." + KEYSTORE_TYPE);
                final File certFile = new File(url.getPath());
                char[] pass = getPassword();

                if (!certFile.exists()) {
                    URL baseUrl = ResourceUtils.getURL(PATH_CERTIFICATE);
                    File folder = new File(baseUrl.getPath());
                    if (!folder.exists()) {
                        folder.mkdirs();
                    }
                    generateKey(certFile, pass, name);
                }

//                certFile = ResourceUtils.getFile(url);
                String path = certFile.getAbsolutePath();
                try (InputStream is = Files.newInputStream(Paths.get(path))) {
                    KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
                    ks.load(is, pass);

                    String alias = getAlias(ks, pass);
                    Certificate[] chain = ks.getCertificateChain(alias);
                    PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pass);

                    if(privateKey == null) {
                        throw new DigitalCertificateException("Private key is not found");
                    }

                    BouncyCastleProvider provider = new BouncyCastleProvider();
                    Security.addProvider(provider);

                    sign(name, absolutePath, absolutePath, chain, privateKey, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                            getReason(formData), getOrganization(), null, null, null, 0);

                }
            }
        } catch (Exception e) {
            LogUtil.error(getClassName(), e, e.getMessage());
            final String parameterName = FormUtil.getElementParameterName(this);
            formData.addFileError(parameterName, e.getMessage());
        }

        return super.formatData(formData);
    }

    protected String getAlias(KeyStore ks, char[] pass) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        String alias = "";
        Enumeration<String> en = ks.aliases();
        while (en.hasMoreElements()) {
            alias = en.nextElement();
            Key key = ks.getKey(alias, pass);
            if (key instanceof PrivateKey) {
                break;
            }
        }
        return alias;
    }


    protected String getReason(FormData formData) {
        // TODO: use Activity Name
        return "Approval";
    }

    public char[] getPassword() {
        SetupManager sm =  (SetupManager) SecurityUtil.getApplicationContext().getBean("setupManager");
        String password = sm.getSettingValue("securityKey");
        return password.isEmpty() ? DEFAULT_PASSWORD.toCharArray() : password.toCharArray();
    }

    public void generateKey(File certFile, char[] pass, String userFullname) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, OperatorCreationException {
        KeyPair generatedKeyPair = generateKeyPair();

        String filename = certFile.getAbsolutePath();
        storeToPKCS12(filename, pass, generatedKeyPair, userFullname);
    }

    public Certificate certificateSign(PrivateKey issuerPrivateKey, X500Name issuerDnName, PublicKey subjectPublicKey, String subjectDN)
            throws OperatorCreationException, CertificateException, IOException {
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

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded());

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuerDnName,
                certSerialNumber, startDate, endDate, dnName, subjectPublicKeyInfo);

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(
                bcProvider).build(issuerPrivateKey);

        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .getCertificate(certificateHolder);
    }

    public void storeToPKCS12(
            String filename, char[] password,
            KeyPair generatedKeyPair, String name){

        try (InputStream is = Files.newInputStream(Paths.get(PATH_CERTIFICATE + ROOT_CERTIFICATE));
             OutputStream os = Files.newOutputStream(Paths.get(filename))) {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(is, password);
            String alias = getAlias(ks, password);
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            Certificate[] chain = ks.getCertificateChain(alias);

            final PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(alias, password);
            final X500Name issuerDn = new JcaX509CertificateHolder(cert).getSubject();
            final PublicKey subjectPublicKey = generatedKeyPair.getPublic();
            final String subjectDn = getDn(name, getOrganizationalUnit(), getOrganization(), getLocality(), getStateOrProvince(), getCountry());

            Certificate certificate = certificateSign(issuerPrivateKey, issuerDn, subjectPublicKey, subjectDn);

            KeyStore pkcs12KeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            pkcs12KeyStore.load(null, null);

            KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(generatedKeyPair.getPrivate(),
                    new Certificate[]{certificate, chain[0]});

            KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
            pkcs12KeyStore.setEntry(name, entry, param);
            pkcs12KeyStore.store(os, password);
        } catch (Exception e){
            LogUtil.error(getClassName(), e, e.getMessage());
        }
    }

    protected String getStateOrProvince() {
        return getPropertyString("stateOrProvince");
    }

    protected String getCountry() {
        return getPropertyString("country");
    }

    protected String getLocality() {
        return getPropertyString("locality");
    }

    protected String getOrganizationalUnit() {
        final String propValue = getPropertyString("organizationalUnit");
        if (!propValue.isEmpty()) {
            return propValue;
        }

        final ExtDirectoryManager directoryManager = (ExtDirectoryManager) AppUtil.getApplicationContext().getBean("directoryManager");

        final String username = WorkflowUtil.getCurrentUsername();
        final User user = directoryManager.getUserById(username);
        final Set<Employment> employments = (Set<Employment>) user.getEmployments();

        return Optional.ofNullable(employments)
                .map(Collection::stream)
                .orElseGet(Stream::empty)
                .map(Employment::getDepartment)
                .map(Department::getName)
                .findFirst()
                .orElse("");
    }

    protected String getOrganization() {
        final String propValue = getPropertyString("organization");
        if (!propValue.isEmpty()) {
            return propValue;
        }

        final ExtDirectoryManager directoryManager = (ExtDirectoryManager) AppUtil.getApplicationContext().getBean("directoryManager");

        final String orgId = WorkflowUtil.getCurrentUserOrgId();
        return Optional.of(orgId)
                .map(directoryManager::getOrganization)
                .map(Organization::getName)
                .orElse("");
    }


    protected String getDn(String commonName, String organizationalUnit, String organization, String locality, String stateOrProvince, String country) {
        return String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", commonName, organizationalUnit, organization, locality, stateOrProvince, country);
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());

        return generator.generateKeyPair();
    }

    public void sign(String name, String src, String dest, Certificate[] chain, PrivateKey pk,
                     String digestAlgorithm, String provider, PdfSigner.CryptoStandard subFilter,
                     String reason, String location, Collection<ICrlClient> crlList,
                     IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize) throws IOException, GeneralSecurityException {

        final String tempFilePath = dest + ".temp";

        try (PdfReader reader = new PdfReader(src);
             PdfWriter writer = new PdfWriter(tempFilePath);
             PdfDocument document = new PdfDocument(reader, writer)) {

            LogUtil.info(getClassName(), "Creating temp file");
        }

        try (PdfReader reader = new PdfReader(tempFilePath);
             OutputStream fos = Files.newOutputStream(Paths.get(dest))) {

            PdfSigner signer = new PdfSigner(reader, fos, new StampingProperties());

            signer.setFieldName(name);
            signer.setSignDate(Calendar.getInstance());
            PdfSignatureAppearance signatureAppearance = signer.getSignatureAppearance();
            signatureAppearance.setReason(reason).setLocation(location);

            IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
            IExternalDigest digest = new BouncyCastleDigest();

            // Sign the document using the detached mode, CMS or CAdES equivalent.
            signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subFilter);
        }
    }

    public boolean isSigned(String path, String username) throws IOException {
        if("true".equalsIgnoreCase(getPropertyString("override"))){
            try (PdfReader pdfReader = new PdfReader(path);
                 PdfDocument pdfDocument = new PdfDocument(pdfReader)) {
                SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
                for (String name : signatureUtil.getSignatureNames()) {
                    if (name.equals(username)) {
                        PdfAcroForm form = PdfAcroForm.getAcroForm(pdfDocument, true);
                        form.flattenFields();
                        return false;
                    }
                }
            }
        }else{
            return true;
        }
        return false;
    }

    public void clearCertificate(PdfDocument pdfDocument){
        PdfAcroForm pdfAcroForm = PdfAcroForm.getAcroForm(pdfDocument, true);

    }

    @Override
    public String getName() {
        return "Digital Certificate";
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
            JSONStream.of(currentPluginProperties, Try.onBiFunction(JSONArray::getJSONObject))
                    .forEach(parentPluginProperties::put);

            return parentPluginProperties.toString().replace("\"", "'");
        } catch (JSONException e) {
            LogUtil.error(getClassName(), e, e.getMessage());
            return super.getPropertyOptions();
        }
    }
}
