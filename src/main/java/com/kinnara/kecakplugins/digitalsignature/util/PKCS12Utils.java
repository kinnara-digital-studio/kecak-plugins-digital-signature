package com.kinnara.kecakplugins.digitalsignature.util;

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

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

public interface PKCS12Utils {
    String PATH_ROOT = "app_certificate/root";
    String ROOT_CERTIFICATE = "root.pkcs12";
    String DEFAULT_PASSWORD = "SuperSecurePasswordNoOneCanBreak";
    String KEYSTORE_TYPE = "pkcs12";
    String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    default void storeToPKCS12(String path,
            Certificate certificate, PrivateKey privateKey, Certificate root){

        try (OutputStream os = Files.newOutputStream(Paths.get(path))) {
            char[] password = getPassword();

            KeyStore pkcs12KeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            pkcs12KeyStore.load(null, null);

            KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(privateKey,
                    new Certificate[]{certificate, root});

            KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
            pkcs12KeyStore.setEntry("Kecak", entry, param);
            pkcs12KeyStore.store(os, password);
        } catch (Exception e){
            LogUtil.error(getClass().getName(), e, e.getMessage());
        }
    }

    default void generatePKCS12(
            String path, char[] password,
            KeyPair generatedKeyPair, String subjectDn){

        try (InputStream is = Files.newInputStream(Paths.get(PATH_ROOT + ROOT_CERTIFICATE))) {

            final PublicKey subjectPublicKey = generatedKeyPair.getPublic();
            PrivateKey issuerPrivateKey = generatedKeyPair.getPrivate();
            X500Name issuerDn = new X500Name(subjectDn);
            Certificate root = null;

            if(is.available() > 0){
                KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
                ks.load(is, password);
                String alias = getAlias(ks, password);
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                Certificate[] chain = ks.getCertificateChain(alias);

                root = chain[0];
                issuerPrivateKey = (PrivateKey) ks.getKey(alias, password);
                issuerDn = new JcaX509CertificateHolder(cert).getSubject();
            }

            Certificate certificate = certificateSign(issuerPrivateKey, issuerDn, subjectPublicKey, subjectDn);

            storeToPKCS12(path, certificate, generatedKeyPair.getPrivate(), root);
        } catch (Exception e){
            LogUtil.error(getClass().getName(), e, e.getMessage());
        }
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
        SetupManager sm =  (SetupManager) SecurityUtil.getApplicationContext().getBean("setupManager");
        String password = sm.getSettingValue("securityKey");
        return (password.isEmpty() ? DEFAULT_PASSWORD : password).toCharArray();
    }
}
