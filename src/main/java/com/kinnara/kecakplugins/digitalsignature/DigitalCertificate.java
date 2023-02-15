package com.kinnara.kecakplugins.digitalsignature;




import com.aspose.pdf.*;
import com.aspose.pdf.facades.PdfFileSignature;
import com.mysql.cj.log.Log;
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;
import java.util.Collection;
import java.util.stream.Stream;


public class DigitalCertificate extends FileUpload {
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
        LogUtil.info(getClassName(), "new plugins 20");
        File fileObj = FileManager.getFileByPath(filePath);

        if(fileObj.isFile()){
            LogUtil.info(getClassName(), "file is true");
        }else{
            LogUtil.info(getClassName(), "file is false");
        }

        String pathObj = fileObj.getAbsolutePath();
        LogUtil.info(getClassName(), "get name : " + fileObj.getName());
        LogUtil.info(getClassName(), "string value of obj file : " + fileObj.toString());

        String path = FileManager.getBaseDirectory();

        LogUtil.info(getClassName(), "base directory : " + path);
        try{
            Document doc = new Document(pathObj);
            LogUtil.info(getClassName(), "doc : " + doc.getFileName());
        }catch(Exception e){
            LogUtil.info(getClassName(), "error : " + e.getMessage());
            throw new RuntimeException(e);
        }

//        PdfFileSignature signature = new PdfFileSignature(doc);

// Create any of the three signature types
//        try {
//            String pathCert = String.valueOf(ResourceUtils.getURL("/resources/certificate.pfx"));
//            PKCS7 pkcs = new PKCS7(pathCert, "asdzxvqwe"); // Use PKCS7/PKCS7Detached objects
//            DocMDPSignature docMdpSignature = new DocMDPSignature(pkcs, DocMDPAccessPermissions.FillingInForms);
//            Rectangle rect = new Rectangle(100, 600, 400, 100);
//// Set signature appearance
//            signature.setSignatureAppearance("aspose-logo.png");
//            signature.certify(1, "Signature Reason", "Contact", "Location", true, rect.toRect(), docMdpSignature);
//// Save digitally signed PDF file
//            signature.save(filePath);
//        } catch (FileNotFoundException e) {
//            throw new RuntimeException(e);
//        }


//        try {
//            File fileCert = ResourceUtils.getFile("/resources/certificate.pfx");
//            DigitalSignOptions options = new DigitalSignOptions(String.valueOf(fileCert));
//            options.setReason("Sign");
//            options.setContact("JohnSmith");
//            options.setLocation("Office1");
//
//            // image as digital certificate appearance on document pages
//            options.setImageFilePath("sample.jpg");
//            options.setAllPages(true);
//            options.setWidth(80);
//            options.setHeight(60);
//            options.setVerticalAlignment(VerticalAlignment.Bottom);
//            options.setHorizontalAlignment(HorizontalAlignment.Right);
//            Padding padding = new Padding();
//            padding.setBottom(10);
//            padding.setRight(10);
//            options.setMargin(padding);
//            SignResult signResult = signature.sign(filePath, options);
//            //add signresult tp form data.
////            formData = FormUtil.
//        } catch (FileNotFoundException e) {
//            throw new RuntimeException(e);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }

//        if(getStoreBinder() == null) {
//            return super.formatData(formData);
//        }

//        FormStoreBinder formStoreBinder = FormUtil.findStoreBinder(this);
//        FormRowSet rowSet = formStoreBinder.store(this, new FormRowSet(), formData);
//        return rowSet;
        return new FormRowSet();
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
