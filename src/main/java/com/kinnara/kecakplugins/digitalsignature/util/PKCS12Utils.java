package com.kinnara.kecakplugins.digitalsignature.util;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
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
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.SetupManager;

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
import java.util.stream.Stream;

public interface PKCS12Utils extends AuditTrailUtil {
    String PATH_USER_CERTIFICATE = "wflow/app_certificate/";
    String PATH_ROOT = "wflow/app_certificate/root";
    String ROOT_KEYSTORE = "root.pkcs12";
    String DEFAULT_PASSWORD = "SuperSecurePasswordNoOneCanBreak";
    String KEYSTORE_TYPE = "pkcs12";
    String SIGNATURE_ALGORITHM = "SHA256WithRSA";

    String DATETIME_FORMAT = "yyyyMMddHHmmss";

    String DEFAULT_DN_ROOT_NAME = "Root Kecak";
    String DEFAULT_DN_ORG = "org.kecak";
    String DEFAULT_DN_ORG_UNIT = "";
    String DEFAULT_DN_LOCALITY = "Bandung";
    String DEFAULT_DN_STATE = "West Java";
    String DEFAULT_DN_COUNTRY = "ID";

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
            String alias = "Kecak";
            if (root == null) {
                entry = new KeyStore.PrivateKeyEntry(privateKey,
                        new Certificate[]{certificate});
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
        generatePKCS12(certificateFile, getPassword(), generatedKeyPair, subjectDn, false);
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

        if(!isRoot){
            final File rootKeystoreFolder = new File(PATH_ROOT);
            File rootKeystoreFile = getLatestKeystore(rootKeystoreFolder, ROOT_KEYSTORE);
            if(!rootKeystoreFile.exists()) {
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

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(
                bcProvider).build(issuerPrivateKey);

        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .getCertificate(certificateHolder);
    }

    default String getAlias(KeyStore ks, char[] pass) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
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
    default File getLatestKeystore(File folder, String filename) {
        if (!folder.exists()) {
            folder.mkdirs();
        }

        return Optional.ofNullable(folder.listFiles())
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(file -> file.getName().endsWith("_" + filename))
                .max(Comparator.comparing(File::getName))
                .orElseGet(() -> getPathCertificateName(folder, filename));
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

    default void signPdf(File userKeystoreFile, File pdfFile, String userFullname, String reason, String organization) throws IOException, GeneralSecurityException, DigitalCertificateException {
        executeAuditTrail("signPdf", userKeystoreFile, pdfFile, userFullname,  reason,  organization);

        char[] pass = getPassword();
        try (InputStream is = Files.newInputStream(userKeystoreFile.toPath())) {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(is, pass);

            String alias = getAlias(ks, pass);
            Certificate[] chain = ks.getCertificateChain(alias);
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pass);
            if (privateKey == null) {
                throw new DigitalCertificateException("Private key is not found in alias [" + alias + "] keystore [" + userKeystoreFile.getAbsolutePath() + "]");
            }

            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);

            signPdf(userFullname, pdfFile, pdfFile, chain, privateKey, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                    reason, organization, null, null, null, 0);

        }
    }

    default void signPdf(String name, File sourcePdfFile, File destPdfFile, Certificate[] chain, PrivateKey pk,
                         String digestAlgorithm, String provider, PdfSigner.CryptoStandard subFilter,
                         String reason, String location, Collection<ICrlClient> crlList,
                         IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize) throws IOException, GeneralSecurityException {

        final Date now = new Date();
        final File tempFile = new File(destPdfFile.getAbsolutePath() + ".temp" + new SimpleDateFormat(DATETIME_FORMAT).format(now));

        try (PdfReader reader = new PdfReader(sourcePdfFile);
             PdfWriter writer = new PdfWriter(tempFile);
             PdfDocument document = new PdfDocument(reader, writer)) {

            LogUtil.debug(getClass().getName(), "Creating temp file [" + tempFile.getAbsolutePath() + "]");
        }

        try (PdfReader reader = new PdfReader(tempFile);
             OutputStream fos = Files.newOutputStream(destPdfFile.toPath())) {

            PdfSigner signer = new PdfSigner(reader, fos, new StampingProperties().useAppendMode());

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

        try (PdfReader reader = new PdfReader(tempFile);
             PdfWriter writer = new PdfWriter(dest);
             PdfDocument pdfDocument = new PdfDocument(reader, writer)) {
            PdfAcroForm acroForm = PdfAcroForm.getAcroForm(pdfDocument, true);
            acroForm.removeField(signatureName);
        }

        if(tempFile.delete()) {
            LogUtil.debug(getClass().getName(), "Temp file [" + tempFile.getAbsolutePath() + "] has been deleted");
        }

    }

}
