package com.kinnara.kecakplugins.digitalsignature;

import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FormBuilderPaletteElement;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormUtil;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

public class DigitalSignature extends Element implements FormBuilderPaletteElement {
    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        String template = "digitalSignature.ftl";

        String formDefId = (String) getProperty("formDefId");
        String signatureId = (String) getProperty("fileField");
        String username = (String) getProperty("username");

        String appId = "";
        String appVersion = "";

        AppDefinition appDef = AppUtil.getCurrentAppDefinition();
        if (appDef != null) {
            appId = appDef.getId();
            appVersion = appDef.getVersion().toString();
        }

        String primaryKeyValue = getPrimaryKeyValue(formData);

        String value = FormUtil.getElementPropertyValue(this, formData);
        if(value!=null) {
            String encodedFileName = value;
            try {
                encodedFileName = URLEncoder.encode(value, "UTF8").replaceAll("\\+", "%20");
            } catch (UnsupportedEncodingException ex) {
                // ignore
            }
            if(encodedFileName!=null && !encodedFileName.equals("")) {
                String fileLocation = FileUtil.getUploadPath(this, primaryKeyValue) + "/" + encodedFileName;
                File file = new File(fileLocation);
                if(file.exists()) {
                    String filePath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + formDefId + "/" + primaryKeyValue + "/" + encodedFileName + ".";
                    dataModel.put("pdfFile", filePath);
                }else {
                    String filePath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + formDefId + "/" + primaryKeyValue + "/" + value + ".";
                    dataModel.put("pdfFile", filePath);
                }
            }else {
                String filePath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + formDefId + "/" + primaryKeyValue + "/" + value + ".";
                dataModel.put("pdfFile", filePath);
            }
        }else{
            dataModel.put("pdfFile", "");
        }
        dataModel.put("className", getClassName());
        String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
        return html;
    }

    @Override
    public String getFormBuilderCategory() {
        return "Kecak";
    }

    @Override
    public int getFormBuilderPosition() {
        return 200;
    }

    @Override
    public String getFormBuilderIcon() {
        return "/plugin/org.joget.apps.form.lib.TextField/images/textField_icon.gif";
    }

    @Override
    public String getFormBuilderTemplate() {
        return "<label class='label' style='position:absolute;top:10px;left:10px;'>Digital Signature</label><div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'><span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:70px;align:center;'>PDF</span><div>";
    }

    @Override
    public String getName() {
        return "Digital Signature";
    }

    @Override
    public String getVersion() {
        return getClass().getPackage().getImplementationVersion();
    }

    @Override
    public String getDescription() {
        return "Digital Signature Form Element";
    }

    @Override
    public String getLabel() {
        return this.getName();
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClass().getName(), "/properties/digitalSignature.json", null, true, "/message/digitalSignature");
    }
}
