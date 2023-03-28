package com.kinnara.kecakplugins.digitalsignature;

import com.kinnara.kecakplugins.digitalsignature.util.Unclutter;
import org.joget.apps.app.dao.FormDefinitionDao;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.model.FormDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.dao.FormDataDao;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FileDownloadSecurity;
import org.joget.apps.form.model.Form;
import org.joget.apps.form.model.FormBuilderPaletteElement;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormService;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;
import org.kecak.apps.exception.ApiException;
import org.springframework.context.ApplicationContext;
import org.springframework.util.ResourceUtils;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Map;
import java.util.ResourceBundle;

@Deprecated
public class DigitalSignature extends Element implements FormBuilderPaletteElement, FileDownloadSecurity, Unclutter {
    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        String template = "digitalSignature.ftl";

        String formDefId = getPropertyString("formDefId");
        String signatureId = getPropertyString("fileField");
        String username = getPropertyString("username");

        String thisFormDefId = "";
        Form form = FormUtil.findRootForm(this);
        if (form != null) {
            thisFormDefId = form.getPropertyString(FormUtil.PROPERTY_ID);
        }

        String appId = "";
        String appVersion = "";

        AppDefinition appDef = AppUtil.getCurrentAppDefinition();
        if (appDef != null) {
            appId = appDef.getId();
            appVersion = appDef.getVersion().toString();
        }

        String primaryKeyValue = getPrimaryKeyValue(formData);
        String value = FormUtil.getElementPropertyValue(this, formData);
        String encodedFileName = value;
        try {
            encodedFileName = URLEncoder.encode(value, "UTF8").replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException ignored) {}

        final String pdfPath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + formDefId + "/" + primaryKeyValue + "/" + encodedFileName + ".";
        dataModel.put("pdfFile", pdfPath);

        dataModel.put("className", getClassName());
        String signaturePath = "/web/json/plugin/" + GetSignatureApi.class.getName() + "/service";
        dataModel.put("signatureFile", signaturePath);
        String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
        return html;
    }

    protected Form generateForm(String formDefId) {
        // proceed without cache
        ApplicationContext appContext = AppUtil.getApplicationContext();
        FormService formService = (FormService) appContext.getBean("formService");
        FormDefinitionDao formDefinitionDao = (FormDefinitionDao) appContext.getBean("formDefinitionDao");

        AppDefinition appDef = AppUtil.getCurrentAppDefinition();

        if (appDef != null && formDefId != null && !formDefId.isEmpty()) {
            FormDefinition formDef = formDefinitionDao.loadById(formDefId, appDef);
            if (formDef != null) {
                String json = formDef.getJson();
                LogUtil.info(this.getClass().getName(), "FORM JSON: " + json);
                return (Form) formService.createElementFromJson(json);
            }
        }
        return null;
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
        return "(Deprecated) Digital Signature";
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

    @Override
    public boolean isDownloadAllowed(Map requestParameters) {
        return true;
    }


}
