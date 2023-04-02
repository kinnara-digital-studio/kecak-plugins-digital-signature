package com.kinnara.kecakplugins.digitalsignature.util;

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
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.commons.util.SetupManager;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.*;

public interface PKCS12Utils {
    String PATH_ROOT = "wflow/app_certificate/root";
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
            KeyStore.Entry entry = null;
            if(root == null){
                entry = new KeyStore.PrivateKeyEntry(privateKey,
                        new Certificate[]{certificate});
            }else{
                entry = new KeyStore.PrivateKeyEntry(privateKey,
                        new Certificate[]{certificate, root});
            }

            LogUtil.info(getClass().getName(), "entry : " + entry);
            KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(password);
            pkcs12KeyStore.setEntry("Kecak", entry, param);
            pkcs12KeyStore.store(os, password);
            LogUtil.info(getClass().getName(), "keystorepkcs12 alias : " + pkcs12KeyStore.getCertificateAlias(certificate));
            LogUtil.info(getClass().getName(), "Save pkcs12 file to : " + path);
        } catch (Exception e){
            LogUtil.error(getClass().getName(), e, e.getMessage());
        }
    }

    default void generatePKCS12(
            String path, char[] password,
            KeyPair generatedKeyPair, String subjectDn) throws ParseException {
        String latestFile = getLatestCertificate(PATH_ROOT, ROOT_CERTIFICATE);
        LogUtil.info(getClass().getName(), "latest file : " + latestFile);
        try (InputStream is = Files.newInputStream(Paths.get(PATH_ROOT + "/" + latestFile))) {

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

    default String getPathCertificateName(String path, String filename) throws FileNotFoundException {
        String timeStamp = new SimpleDateFormat("yyyyMMddHHmmss").format(new java.util.Date());
        URL url = ResourceUtils.getURL(path + "/" + timeStamp + "_" + filename);
        File certFile = new File(url.getPath());

        return certFile.getAbsolutePath();
    }

    default String getLatestCertificate(String pathFolder, String filename) throws ParseException {
        File folder = new File(pathFolder);
        File[] listOfFiles = folder.listFiles();
        List<Date> dateList = new ArrayList<>();
        String latestDate = "";

        for (int i = 0; i < listOfFiles.length; i++) {
            //get date
            String[] temp = listOfFiles[i].getName().split("_");
            Date date = new SimpleDateFormat("yyyyMMddHHmmss").parse(temp[0]);
            dateList.add(date);
        }
        if(!dateList.isEmpty()){
            Date latest = Collections.max(dateList);
            latestDate = new SimpleDateFormat("yyyyMMddHHmmss").format(latest) + "_";
        }

        return latestDate + filename;
    }
}
