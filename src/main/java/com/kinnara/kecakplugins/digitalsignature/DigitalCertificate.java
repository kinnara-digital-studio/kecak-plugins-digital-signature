package com.kinnara.kecakplugins.digitalsignature;





import com.lowagie.text.DocumentException;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.*;
import com.lowagie.text.pdf.PdfPKCS7;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.lib.FileUpload;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.PluginManager;
import org.json.JSONArray;
import org.json.JSONException;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Collection;
import java.util.stream.Stream;


public class DigitalCertificate extends FileUpload{
    private static final int ESTIMATED_SIGNATURE_SIZE = 8192;
    private byte[] certificateChain;
    private Certificate[] certificates;
    private PrivateKey privateKey;
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

        String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
        return html;
    }

    public FormRowSet formatData(FormData formData) {

        String filePath = FormUtil.getElementPropertyValue(this, formData);
        LogUtil.info(getClassName(), "filepath to tomcat : " + filePath);
        //get uploaded file from app_temp
        LogUtil.info(getClassName(), "new plugins 36");
        File fileObj = FileManager.getFileByPath(filePath);

        try {

            //get key
            File certFile = ResourceUtils.getFile("wflow/app_certificate/newCert.pfx");
//            File test = FileManager.getFileByPath("resources/certificate.pfx");
            String pathTest = certFile.getAbsolutePath();
            LogUtil.info(getClassName(), "filepath : " + pathTest);
            InputStream inputKey = new FileInputStream(certFile);
            LogUtil.info(getClassName(), "input key : " + inputKey.toString());
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputKey, "asdzxvqwe".toCharArray());

            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("person1");

            privateKey = (PrivateKey) keyStore.getKey("person1", "asdzxvqwe".toCharArray());
            certificateChain = certificate.getEncoded();
            certificates = new Certificate[]{(Certificate) certificate};
            if(keyStore.isCertificateEntry("person1")){
                LogUtil.info(getClassName(), "keystore : " + keyStore);
                LogUtil.info(getClassName(), "type : " + keyStore.getType());
            }

            //get pdf file
            InputStream inputStream = new FileInputStream(fileObj);
            ByteArrayOutputStream output = new ByteArrayOutputStream();

            sign(IOUtils.toByteArray(inputStream), output);

            File result = new File(filePath);
            FileUtils.writeByteArrayToFile(result, output.toByteArray());

        } catch (FileNotFoundException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            LogUtil.error(getClassName(), e, e.getMessage());
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

//        if(getStoreBinder() == null) {
//            return super.formatData(formData);
//        }

//        FormStoreBinder formStoreBinder = FormUtil.findStoreBinder(this);
//        FormRowSet rowSet = formStoreBinder.store(this, new FormRowSet(), formData);
//        return rowSet;
        return new FormRowSet();
    }

    public void sign(byte[] document, ByteArrayOutputStream output) throws IOException, DocumentException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        PdfReader pdfReader = new PdfReader(document);

        PdfStamper signer = PdfStamper.createSignature(pdfReader, output, '\0');

        Calendar signDate = Calendar.getInstance();

        int page = 1;

        PdfSignature pdfSignature = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        pdfSignature.setReason("Reason to sign");
        pdfSignature.setLocation("Location of signature");
        pdfSignature.setContact("Person Name");
        pdfSignature.setDate(new PdfDate(signDate));
        pdfSignature.setCert(certificateChain);

        PdfSignatureAppearance appearance = createAppearance(signer, page, pdfSignature);

        PdfPKCS7 sgn = new PdfPKCS7((PrivateKey) null, (java.security.cert.Certificate[]) certificates, null, "SHA-256", null, false);
        InputStream data = appearance.getRangeStream();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(IOUtils.toByteArray(data));
        byte[] appeareanceHash = digest.digest();

        byte[] hashToSign = sgn.getAuthenticatedAttributeBytes(appeareanceHash, appearance.getSignDate(), null);

        byte[] signedHash = addDigitalSignatureToHash(hashToSign);

        sgn.setExternalDigest(signedHash, null, "RSA");
        byte[] encodedPKCS7 = sgn.getEncodedPKCS7(appeareanceHash, appearance.getSignDate());

        byte[] paddedSig = new byte[ESTIMATED_SIGNATURE_SIZE];

        System.arraycopy(encodedPKCS7, 0, paddedSig, 0, encodedPKCS7.length);

        PdfDictionary dictionary = new PdfDictionary();
        dictionary.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        appearance.close(dictionary);
    }

    private PdfSignatureAppearance createAppearance(PdfStamper signer, int page, PdfSignature pdfSignature) throws IOException, DocumentException {
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setRender(PdfSignatureAppearance.SignatureRenderDescription);
        appearance.setAcro6Layers(true);

        int lowerLeftX = 570;
        int lowerLeftY = 70;
        int width = 370;
        int height = 150;
        appearance.setVisibleSignature(new Rectangle(lowerLeftX, lowerLeftY, width, height), page, null);

        appearance.setCryptoDictionary(pdfSignature);
        appearance.setCrypto((PrivateKey) null, (java.security.cert.Certificate[]) certificates, null, PdfName.FILTER);

        HashMap<Object, Object> exclusions = new HashMap<>();
        exclusions.put(PdfName.CONTENTS, ESTIMATED_SIGNATURE_SIZE * 2 + 2);
        appearance.preClose(exclusions);

        return appearance;
    }

    public byte[] addDigitalSignatureToHash(byte[] hashToSign) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        java.security.Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hashToSign);

        return signature.sign();
    }

    @Override
    public String getName() {
        return "Upload DigiCert-able File";
    }

    @Override
    public String getVersion() {
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        ResourceBundle resourceBundle = pluginManager.getPluginMessageBundle(getClassName(), "/message/BuildNumber");
        String buildNumber = resourceBundle.getString("buildNumber");
        return buildNumber;
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
