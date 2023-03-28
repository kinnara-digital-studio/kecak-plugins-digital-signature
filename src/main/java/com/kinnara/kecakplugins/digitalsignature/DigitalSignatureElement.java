package com.kinnara.kecakplugins.digitalsignature;

import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FormUtil;
import org.joget.plugin.base.PluginManager;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.ResourceBundle;

public class DigitalSignatureElement extends Element implements FormBuilderPaletteElement, FileDownloadSecurity {
    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        final String template = "DigitalSignatureElement.ftl";
        dataModel.put("className", getClassName());

        final AppDefinition appDefinition = AppUtil.getCurrentAppDefinition();
        final Form form = FormUtil.findRootForm(this);
        final String appId = appDefinition.getAppId();
        final long appVersion = appDefinition.getVersion();
        final String formDefId = form.getPropertyString(FormUtil.PROPERTY_ID);
        final String primaryKeyValue = formData.getPrimaryKeyValue();
        final String value = FormUtil.getElementPropertyValue(this, formData);
        String encodedFileName = value;
        try {
            encodedFileName = URLEncoder.encode(value, "UTF8").replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException ex) {
            // ignore
        }
        final String pdfPath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + formDefId + "/" + primaryKeyValue + "/" + encodedFileName + ".";
        dataModel.put("pdfPath", pdfPath);
        String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
        return html;
    }

    @Override
    public boolean isDownloadAllowed(Map map) {
        return true;
    }

    @Override
    public String getFormBuilderCategory() {
        return "Digital Signature";
    }

    @Override
    public int getFormBuilderPosition() {
        return 100;
    }

    @Override
    public String getFormBuilderIcon() {
        return null;
    }

    @Override
    public String getFormBuilderTemplate() {
        return "<h1>test</h1>";
    }

    @Override
    public String getName() {
        return getLabel();
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
        return "Digital Signature";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/DigitalSignatureElement.json", null, true, "/message/DigitalCertificate");
    }
}
