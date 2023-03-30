package com.kinnara.kecakplugins.digitalsignature;

import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.PluginManager;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ResourceBundle;

public class RootCertificateStoreBinder extends FormBinder implements FormStoreElementBinder, PKCS12Utils {
    @Override
    public FormRowSet store(Element element, FormRowSet formRowSet, FormData formData) {

        FormRow datas = formRowSet.get(0);
        String pathCert = datas.getTempFilePath("certificate");
        String pathKey = datas.getTempFilePath("privatekey");
//        File cert = FileManager.getFileByPath(pathCert);
//        File key = FileManager.getFileByPath(pathKey);

        LogUtil.info(getClassName(), "cert path from rowset : " + pathCert);
        LogUtil.info(getClassName(), "pk path from rowset : " + pathKey);


        // get form
        Form form = FormUtil.findRootForm(this.getElement());

        // get elements
        Element elementCertl = FormUtil.findElement("certificate", form, formData);
        Element elementPrivateKey = FormUtil.findElement("privatekey", form, formData);

        // get path
        String certPath = FormUtil.getElementPropertyValue(elementCertl, formData);
        String privatekeyPath = FormUtil.getElementPropertyValue(elementPrivateKey, formData);

        LogUtil.info(getClassName(), "cert path from formData : " + certPath);
        LogUtil.info(getClassName(), "pk path from formData : " + privatekeyPath);

        URL baseUrl = null;
        try {
            baseUrl = ResourceUtils.getURL(PATH_ROOT);
            File folder = new File(baseUrl.getPath());
            if (!folder.exists()) {
                folder.mkdirs();
            }

            //get certificate
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            FileInputStream fis = new FileInputStream(certPath);
            final Certificate certificate = fac.generateCertificate(fis);

            //get private key
            File privatekeyFile = FileManager.getFileByPath(privatekeyPath);
            FileReader fr = new FileReader(privatekeyFile);
            final PrivateKey privateKey = getPrivateKeyFromPEM(fr);
            final String pathName = PATH_ROOT + "/" + ROOT_CERTIFICATE;

            storeToPKCS12(pathName, certificate, privateKey, null);
        } catch (CertificateException | IOException e) {
            LogUtil.error(getClassName(), e, e.getMessage());
        }

        return formRowSet;
    }

    private static PrivateKey getPrivateKeyFromPEM(Reader reader) throws IOException {

        PrivateKey key;

        try (PEMParser pem = new PEMParser(reader)) {
            JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
            Object pemContent = pem.readObject();
            if (pemContent instanceof PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair) pemContent;
                KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
                key = keyPair.getPrivate();
            } else if (pemContent instanceof PrivateKeyInfo) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemContent;
                key = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
            } else {
                throw new IllegalArgumentException("Unsupported private key format '" +
                        pemContent.getClass().getSimpleName() + '"');
            }
        }

        return key;
    }


    @Override
    public String getName() {
        return "Root Certificate";
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
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClass().getName(), "/properties/RootCertificate.json", null, true, "/message/RootCertificate");
    }
}
