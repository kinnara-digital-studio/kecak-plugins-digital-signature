package com.kinnara.kecakplugins.digitalsignature.binder;

import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import org.bouncycastle.util.encoders.Base64;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.PluginManager;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ResourceBundle;

/**
 * Binder to store root certificate
 */
public class RootCertificateStoreBinder extends FormBinder implements FormStoreElementBinder, PKCS12Utils {
    @Override
    public FormRowSet store(Element element, FormRowSet formRowSet, FormData formData) {

        FormRow row = formRowSet.get(0);
        String pathCert = row.getTempFilePath("certificate");
        String pathKey = row.getTempFilePath("privatekey");

        LogUtil.info(getClassName(), "cert path from rowset : " + pathCert);
        LogUtil.info(getClassName(), "pk path from rowset : " + pathKey);



        try {
            final URL baseUrl = ResourceUtils.getURL(PATH_ROOT);
            final File folder = new File(baseUrl.getPath());
            if (!folder.exists()) {
                folder.mkdirs();
            }

            //get certificate
            final CertificateFactory fac = CertificateFactory.getInstance("X509");
            try(FileInputStream fis = new FileInputStream(FileManager.getBaseDirectory() + "/" + pathCert)) {

                final Certificate certificate = fac.generateCertificate(fis);

                //get private key
                final PrivateKey privateKey = getPemPrivateKey(FileManager.getBaseDirectory() + "/" + pathKey);
                final File rootKeystore = getPathCertificateName(new File(PATH_ROOT), ROOT_KEYSTORE);
                storeToPKCS12(rootKeystore, certificate, privateKey, null);
            }
        } catch (Exception e) {
            LogUtil.error(getClassName(), e, e.getMessage());
        }

        return null;
    }

    public  PrivateKey getPemPrivateKey(String filename) throws Exception {
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);
        String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
        LogUtil.info(getClassName(), "private key : " + privKeyPEM);

        Base64 b64 = new Base64();
        byte [] decoded = b64.decode(privKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
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
