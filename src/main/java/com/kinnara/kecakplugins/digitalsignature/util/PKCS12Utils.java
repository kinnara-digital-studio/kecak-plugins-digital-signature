package com.kinnara.kecakplugins.digitalsignature.util;

import com.itextpdf.bouncycastle.cert.ocsp.BasicOCSPRespBC;
import com.itextpdf.commons.bouncycastle.cert.ocsp.IBasicOCSPResp;
import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import com.kinnara.kecakplugins.digitalsignature.AdobeLtvEnabling;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.webapi.GetTimeStampApi;
import com.kinnarastudio.commons.Try;
import com.lowagie.text.pdf.TSAClient;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfStamper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.x509.util.StreamParsingException;
import org.javatuples.Pair;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.SetupManager;
import org.kecak.apps.exception.ApiException;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public interface PKCS12Utils extends AuditTrailUtil {
    String PATH_USER_CERTIFICATE = "wflow/app_certificate/";
    String PATH_ROOT = "wflow/app_certificate/root";
    String DEFAULT_PASSWORD = "SuperSecurePasswordNoOneCanBreak";
    String KEYSTORE_TYPE = "pkcs12";
    String ROOT_KEYSTORE = "root." + KEYSTORE_TYPE;
    String USER_KEYSTORE = "certificate." + KEYSTORE_TYPE;
    String SIGNATURE_ALGORITHM = "SHA256WithRSA";

    String DATETIME_FORMAT = "yyyyMMddHHmmss";

    String DEFAULT_DN_ROOT_NAME = "Root Kecak";
    String DEFAULT_DN_ORG = "org.kecak";
    String DEFAULT_DN_ORG_UNIT = "";
    String DEFAULT_DN_LOCALITY = "Bandung";
    String DEFAULT_DN_STATE = "West Java";
    String DEFAULT_DN_COUNTRY = "ID";

    String LOCAL_TSA_URL = "http://localhost:8080/web/json/plugin/" + GetTimeStampApi.class.getName() + "/service";


    /**
     * @param keystoreFile
     * @param certificate
     * @param privateKey
     * @param root
     * @return keystore file containing private key and certificate
     * @throws DigitalCertificateException
     */
    default void storeToPKCS12(File keystoreFile,
                               Certificate certificate, PrivateKey privateKey, Certificate root) throws DigitalCertificateException {

        try (OutputStream os = Files.newOutputStream(keystoreFile.toPath())) {
            char[] password = getPassword();

            KeyStore pkcs12KeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            pkcs12KeyStore.load(null, null);
            KeyStore.Entry entry;
            String alias;
            if (root == null) {
                entry = new KeyStore.PrivateKeyEntry(privateKey,
                        new Certificate[]{certificate});
                alias = "Kecak Workflow";
            } else {
                entry = new KeyStore.PrivateKeyEntry(privateKey,
                        new Certificate[]{certificate, root});
                alias = "Root";
            }

            KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
            pkcs12KeyStore.setEntry(alias, entry, param);
            pkcs12KeyStore.store(os, password);

            if (!keystoreFile.exists()) {
                throw new DigitalCertificateException("Error generating file [" + keystoreFile.getAbsolutePath() + "]");
            }

        } catch (DigitalCertificateException | KeyStoreException | IOException | NoSuchAlgorithmException |
                 CertificateException e) {
            throw new DigitalCertificateException(e);
        }
    }

    default void generateRootKey(File certificateFile) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, OperatorCreationException, ParseException, UnrecoverableKeyException, DigitalCertificateException {
        KeyPair generatedKeyPair = generateKeyPair();
        String subjectDn = getDn(DEFAULT_DN_ROOT_NAME, DEFAULT_DN_ORG_UNIT, DEFAULT_DN_ORG, DEFAULT_DN_LOCALITY, DEFAULT_DN_STATE, DEFAULT_DN_COUNTRY);
        generatePKCS12(certificateFile, getPassword(), generatedKeyPair, subjectDn, true);
    }

    /**
     * @param userKeystoreFile
     * @param password
     * @param generatedKeyPair
     * @param subjectDn
     * @return keystore file containing private key and certificate
     * @throws ParseException
     * @throws DigitalCertificateException
     * @throws CertificateException
     * @throws OperatorCreationException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */

    default void generatePKCS12(
            File userKeystoreFile, char[] password,
            KeyPair generatedKeyPair, String subjectDn, boolean isRoot) throws ParseException, DigitalCertificateException, CertificateException, OperatorCreationException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, IOException {

        final PublicKey subjectPublicKey = generatedKeyPair.getPublic();
        PrivateKey issuerPrivateKey = generatedKeyPair.getPrivate();
        X500Name issuerDn = new X500Name(subjectDn);
        Certificate root = null;

        if (!isRoot) {
            final File pathRoot = new File(PATH_ROOT);
            Optional<File> optRootKeystoreFile = optLatestKeystore(pathRoot, ROOT_KEYSTORE);
            final File rootKeystoreFile;
            if (optRootKeystoreFile.map(File::exists).orElse(false)) {
                rootKeystoreFile = optRootKeystoreFile.get();
            } else {
                rootKeystoreFile = getPathCertificateName(pathRoot, ROOT_KEYSTORE);
                generateRootKey(rootKeystoreFile);
            }

            try (InputStream rootKeystoreInputStream = Files.newInputStream(rootKeystoreFile.toPath())) {

                KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
                ks.load(rootKeystoreInputStream, password);
                String alias = getAlias(ks, password);
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                Certificate[] chain = ks.getCertificateChain(alias);

                issuerPrivateKey = (PrivateKey) ks.getKey(alias, password);
                issuerDn = new JcaX509CertificateHolder(cert).getSubject();
                root = chain[0];
            }
        }

        Certificate certificate = certificateSign(issuerPrivateKey, issuerDn, subjectPublicKey, subjectDn);
        storeToPKCS12(userKeystoreFile, certificate, generatedKeyPair.getPrivate(), root);
    }

    default Certificate certificateSign(PrivateKey issuerPrivateKey, X500Name issuerDnName, PublicKey subjectPublicKey, String subjectDN)
            throws OperatorCreationException, CertificateException {
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

        try {
            certificateBuilder.addExtension(X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
            LogUtil.info(getClass().getName(), "EXTENDEDKEYUSAGE SUCCESS");
        } catch (CertIOException e) {
            LogUtil.error(getClass().getName(), e, "ERROR EXTENDEDKEYUSAGE : " + e.getMessage());
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(bcProvider)
                .build(issuerPrivateKey);

        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .getCertificate(certificateHolder);
    }

    default String getAlias(KeyStore ks, char[] pass) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Enumeration<String> en = ks.aliases();
        while (en.hasMoreElements()) {
            String alias = en.nextElement();
            Key key = ks.getKey(alias, pass);
            if (key instanceof PrivateKey) {
                return alias;
            }
        }
        return "";
    }

    default char[] getPassword() {
        SetupManager sm = (SetupManager) SecurityUtil.getApplicationContext().getBean("setupManager");
        String password = sm.getSettingValue("securityKey");
        return (password.isEmpty() ? DEFAULT_PASSWORD : password).toCharArray();
    }

    default File getPathCertificateName(File containerFolder, String filename) {
        final Date now = new Date();
        final String timeStamp = new SimpleDateFormat(DATETIME_FORMAT).format(now);
        return new File(containerFolder.getAbsolutePath() + "/" + timeStamp + "_" + filename);
    }

    /**
     * @param folder
     * @param filename
     * @return
     */
    default Optional<File> optLatestKeystore(File folder, String filename) {
        if (!folder.exists()) {
            folder.mkdirs();
        }

        return Optional.ofNullable(folder.listFiles())
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(file -> file.getName().endsWith("_" + filename))
                .max(Comparator.comparing(File::getName));
    }

    default Certificate[] getCertificateChain(File certificateFile, char[] password) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        try (InputStream is = Files.newInputStream(certificateFile.toPath())) {
            final KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(is, password);
            final String alias = getAlias(ks, password);
            Certificate[] chain = ks.getCertificateChain(alias);
            return chain;
        }
    }

    default PrivateKey getPrivateKey(File certificateFile, char[] password) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, DigitalCertificateException {
        try (InputStream is = Files.newInputStream(certificateFile.toPath())) {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(is, password);

            String alias = getAlias(ks, password);
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);

            if (privateKey == null) {
                throw new DigitalCertificateException("Private key is not found");
            }

            return privateKey;
        }
    }

    default Provider getSecurityProvider() {
        final Provider securityProvider = new BouncyCastleProvider();
        Security.addProvider(securityProvider);
        return securityProvider;
    }


    default String getDn(String commonName, String organizationalUnit, String organization, String locality, String stateOrProvince, String country) {
        return String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", commonName, organizationalUnit, organization, locality, stateOrProvince, country);
    }

    default KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        return generator.generateKeyPair();
    }

    default void signPdf(File userKeystoreFile, File pdfFile, String userFullname, String reason, String organization, boolean useTimeStamp, String tsaUrl, String tsaUsername, String tsaPassword) throws IOException, GeneralSecurityException, DigitalCertificateException {
        executeAuditTrail("signPdf", userKeystoreFile, pdfFile, userFullname, reason, organization);

        char[] pass = getPassword();
        try (InputStream is = Files.newInputStream(userKeystoreFile.toPath())) {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(is, pass);

            Pair<Certificate[], PrivateKey> extractedKs = extractKeystore(userKeystoreFile, pass);
            Certificate[] chain = extractedKs.getValue0();
            PrivateKey privateKey = extractedKs.getValue1();
            Provider provider = new BouncyCastleProvider();
            Security.addProvider(provider);

            final ITSAClient tsaClient;
            if (useTimeStamp) {
                tsaClient = getTsaClient(tsaUrl, tsaUsername, tsaPassword);
            } else {
                tsaClient = null;
            }

            IOcspClient ocspClient = getOcspClient();
            Collection<ICrlClient> crlList = Collections.singletonList(new CrlClientOnline());

            signPdf(userFullname, pdfFile, pdfFile, chain, privateKey, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                    reason, organization, crlList, ocspClient, tsaClient, 0);
        }
    }

    default Pair<Certificate[], PrivateKey> extractKeystore(File keystore, char[] pass) throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, DigitalCertificateException {
        try (InputStream is = Files.newInputStream(keystore.toPath())) {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(is, pass);

            String alias = getAlias(ks, pass);
            Certificate[] chain = ks.getCertificateChain(alias);
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pass);
            if (privateKey == null) {
                throw new DigitalCertificateException("Private key is not found in alias [" + alias + "] keystore [" + keystore.getAbsolutePath() + "]");
            }

            return Pair.with(chain, privateKey);
        }
    }

    default void signPdf(String name, File sourcePdfFile, File destPdfFile, Certificate[] chain, PrivateKey pk,
                         String digestAlgorithm, String provider, PdfSigner.CryptoStandard subFilter,
                         String reason, String location, Collection<ICrlClient> crlList,
                         IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize) throws IOException, GeneralSecurityException {

        //ltvEnable
        makeLtvEnable(sourcePdfFile, destPdfFile);

        final Date now = new Date();
        final File tempFile = new File(destPdfFile.getAbsolutePath() + ".temp" + new SimpleDateFormat(DATETIME_FORMAT).format(now));

        try (PdfReader reader = new PdfReader(sourcePdfFile);
             PdfWriter writer = new PdfWriter(tempFile);
             PdfDocument document = new PdfDocument(reader, writer, new StampingProperties().preserveEncryption().useAppendMode())) {

            LogUtil.debug(getClass().getName(), "Creating temp file [" + tempFile.getAbsolutePath() + "]");
        }

        try (PdfReader pdfReader = new PdfReader(tempFile);
             OutputStream fos = Files.newOutputStream(destPdfFile.toPath())) {

            final PdfSigner signer = new PdfSigner(pdfReader, fos, new StampingProperties().preserveEncryption().useAppendMode());
            signer.setFieldName(name);
            signer.setSignDate(Calendar.getInstance());

            final PdfSignatureAppearance signatureAppearance = signer.getSignatureAppearance();
            signatureAppearance.setReason(reason).setLocation(location);

            IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
            IExternalDigest digest = new BouncyCastleDigest();

            // Sign the document using the detached mode, CMS or CAdES equivalent.
            signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subFilter);
        }
    }

    default void ltvEnable(PdfSigner signer, ByteArrayOutputStream baos, OutputStream os, String name,
                           OcspClientBouncyCastle ocspClient, CrlClientOnline crlClient, ITSAClient tsc) {
        ByteArrayInputStream signedPdfInput = new ByteArrayInputStream(baos.toByteArray());
        try {
            PdfReader pdfReader = new PdfReader(signedPdfInput);
            PdfDocument document = new PdfDocument(pdfReader.setUnethicalReading(true), new PdfWriter(os),
                    new StampingProperties().useAppendMode());
            LtvVerification ltvVerification = new LtvVerification(document);
            ltvVerification.addVerification(name, ocspClient, crlClient, LtvVerification.CertificateOption.WHOLE_CHAIN,
                    LtvVerification.Level.OCSP_CRL, LtvVerification.CertificateInclusion.YES);
            ltvVerification.merge();
            document.getCatalog().getPdfObject().getAsDictionary(PdfName.DSS).getAsArray(PdfName.Certs)
                    .add(new PdfStream(
                            IOUtils.toByteArray(getClass().getClassLoader().getResourceAsStream("HPARCA_CA.cer"))));
            document.close();
            pdfReader.close();

        } catch (IOException | GeneralSecurityException e) {
            LogUtil.error(getClass().getName(), e, "Error while making signature ltv enabled");
        }
    }

    default boolean isSigned(File pdfFile, String userFullName) throws IOException {
        try (PdfReader pdfReader = new PdfReader(pdfFile);
             PdfDocument pdfDocument = new PdfDocument(pdfReader)) {

            SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
            for (String name : signatureUtil.getSignatureNames()) {
                if (name.equals(userFullName)) {
                    return true;
                }
            }
        }
        return false;
    }

    default void eraseSignature(File file, String signatureName) throws IOException {
        eraseSignature(file, file, signatureName);
    }

    default void eraseSignature(File src, File dest, String signatureName) throws IOException {
        final File tempFile = new File(dest.getAbsolutePath() + ".temp");

        try (PdfReader reader = new PdfReader(src);
             PdfWriter writer = new PdfWriter(tempFile);
             PdfDocument document = new PdfDocument(reader, writer)) {
            LogUtil.debug(getClass().getName(), "Creating temp file [" + tempFile.getAbsolutePath() + "]");
        }

//        try(
////             PdfReader readerTemp = new PdfReader(tempFile);
//             PdfWriter writerDest = new PdfWriter(dest)) {
//
//            com.lowagie.text.pdf.PdfReader readerAcro = new com.lowagie.text.pdf.PdfReader(tempFile.toURL());
//            AcroFields acroFields = readerAcro.getAcroFields();
//            LogUtil.info(getClass().getName(), "Test acro : " + acroFields.getSignatureNames().get(1));
//            LogUtil.info(getClass().getName(), "Signature name : " + signatureName);
//            acroFields.removeField(signatureName);
//            PdfStamper pdfStamper = new PdfStamper(readerAcro, writerDest);
//            pdfStamper.close();
//        } catch (DocumentException e) {
//            LogUtil.error(getClass().getName(), e, e.getMessage());
//        }

        try (PdfReader reader = new PdfReader(tempFile);
             PdfWriter writer = new PdfWriter(dest);
             PdfDocument pdfDocument = new PdfDocument(reader, writer)) {
            PdfAcroForm acroForm = PdfAcroForm.getAcroForm(pdfDocument, true);
            acroForm.removeField(signatureName);
        }

        if (tempFile.delete()) {
            LogUtil.debug(getClass().getName(), "Temp file [" + tempFile.getAbsolutePath() + "] has been deleted");
        }

    }

    default byte[] getTimeStampResponse(byte[] tsqBytes) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, ParseException, TSPException, OperatorCreationException, DigitalCertificateException {
        TimeStampRequest timeStampRequest = new TimeStampRequest(tsqBytes);
        TimeStampResponse timeStampResponse = getTimeStampResponse(timeStampRequest);
        return timeStampResponse.getEncoded();
    }

    default TimeStampResponse getTimeStampResponse(TimeStampRequest timeStampRequest) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, ParseException, OperatorCreationException, DigitalCertificateException, TSPException {
        JcaSimpleSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSimpleSignerInfoGeneratorBuilder();

        final File pathRoot = new File(PATH_ROOT);
        final Optional<File> optRootKeystoreFile = optLatestKeystore(pathRoot, ROOT_KEYSTORE);
        final File rootKeystoreFile;

        if (optRootKeystoreFile.map(File::exists).orElse(false)) {
            rootKeystoreFile = optRootKeystoreFile.get();
        } else {
            rootKeystoreFile = getPathCertificateName(pathRoot, ROOT_KEYSTORE);
            generateRootKey(rootKeystoreFile);
        }
        Pair<Certificate[], PrivateKey> extractedKs = extractKeystore(rootKeystoreFile, getPassword());
        X509Certificate rootCertificate = Optional.of(extractedKs)
                .map(Pair::getValue0)
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .findAny()
                .orElseThrow(() -> new DigitalCertificateException("Error retrieving root certificate"));

        SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(SIGNATURE_ALGORITHM, extractedKs.getValue1(), rootCertificate);
        String policyId = getClass().getPackage().getImplementationVersion();

        DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1);

        TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(signerInfoGenerator, digestCalculator, new ASN1ObjectIdentifier(policyId));
        TimeStampResponseGenerator responseGenerator = new TimeStampResponseGenerator(tokenGenerator, TSPAlgorithms.ALLOWED);

        Date now = new Date();
        return responseGenerator.generate(timeStampRequest, BigInteger.valueOf(now.getTime()), now);
    }

    default ITSAClient getTsaClient(String url, String username, String password) {
        return new TSAClientBouncyCastle(url, username, password) {

            /**
             * Bypassing Http URL connection since api {@link GetTimeStampApi}
             * uses the same {@link PKCS12Utils#getTimeStampResponse(byte[])} library
             *
             * @param requestBytes is a byte representation of TSA request
             *
             * @return
             * @throws IOException
             */
            @Override
            protected byte[] getTSAResponse(byte[] requestBytes) throws IOException {
                // handle with default implementation
                if (url != null && !url.isEmpty()) {
                    return super.getTSAResponse(requestBytes);
                }

                // use current server as TSA, bypass request through API
                else {
                    try {
                        return getTimeStampResponse(requestBytes);
                    } catch (UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException |
                             KeyStoreException | ParseException | TSPException | OperatorCreationException |
                             DigitalCertificateException e) {

                        LogUtil.error(getClass().getName(), e, "Error bypassing getTSAResponse, try to use HTTP connection");
                        return super.getTSAResponse(requestBytes);
                    }
                }
            }
        };
    }

    default IOcspClient getOcspClient() {
        return new OcspClientBouncyCastle(null);
//        try (PdfReader reader = new PdfReader(pdfFile);
//             PdfDocument document = new PdfDocument(reader)) {
//
//            SignatureUtil signatureUtil = new SignatureUtil(document);
//            List<IBasicOCSPResp> ocsps = signatureUtil.getSignatureNames().stream()
//                    .map(signatureUtil::readSignatureData)
//                    .map(PdfPKCS7::getOcsp)
//                    .map(o -> (BasicOCSPRespBC) o)
//                    .map(BasicOCSPRespBC::getBasicOCSPResp)
//                    .map(BasicOCSPRespBC::new)
//                    .collect(Collectors.toList());
//
//            OCSPVerifier ocspVerifier = new OCSPVerifier(null, ocsps);
//            return new OcspClientBouncyCastle(ocspVerifier);
//        } catch (Exception e) {
//            LogUtil.error(getClass().getName(), e, e.getMessage());
//            return null;
//        }
    }

    default void makeLtvEnable(File sourcePdfFile, File destPdfFile) throws IOException {
        final Date now = new Date();
        final File tempFile = new File(destPdfFile.getAbsolutePath() + ".temp" + new SimpleDateFormat(DATETIME_FORMAT).format(now));
        try (PdfReader reader = new PdfReader(sourcePdfFile);
             PdfWriter writer = new PdfWriter(tempFile);
             PdfDocument document = new PdfDocument(reader, writer, new StampingProperties().preserveEncryption().useAppendMode())) {

            LogUtil.debug(getClass().getName(), "Creating temp file [" + tempFile.getAbsolutePath() + "]");
        }

        try (PdfReader pdfReader = new PdfReader(tempFile);
             PdfWriter pdfWriter = new PdfWriter(destPdfFile);
             PdfDocument pdfDocument = new PdfDocument(pdfReader, pdfWriter,
                     new StampingProperties().preserveEncryption().useAppendMode())) {

            AdobeLtvEnabling adobeLtvEnabling = new AdobeLtvEnabling(pdfDocument);
            IOcspClient ocsp = getOcspClient();
            ICrlClient crl = new CrlClientOnline();
            adobeLtvEnabling.enable(ocsp, crl);

            if (tempFile.delete()) {
                LogUtil.debug(getClass().getName(), "Temp file [" + tempFile.getAbsolutePath() + "] has been deleted");
            }
        } catch (OCSPException | GeneralSecurityException | StreamParsingException | IOException |
                 OperatorException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
        }

    }

}
