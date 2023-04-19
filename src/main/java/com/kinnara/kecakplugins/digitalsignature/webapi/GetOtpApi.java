package com.kinnara.kecakplugins.digitalsignature.webapi;

import com.kinnara.kecakplugins.digitalsignature.util.OtpUtil;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.model.PackageActivityForm;
import org.joget.apps.app.service.AppService;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.Form;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.service.FormUtil;
import org.joget.apps.workflow.lib.AssignmentCompleteButton;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.model.WorkflowProcessResult;
import org.joget.workflow.util.WorkflowUtil;
import org.kecak.apps.exception.ApiException;
import org.springframework.context.ApplicationContext;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.ResourceBundle;

public class GetOtpApi extends ExtDefaultPlugin implements PluginWebSupport, OtpUtil {
    @Override
    public String getName() {
        return "Get OTP API";
    }

    @Override
    public String getVersion() {
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        ResourceBundle resourceBundle = pluginManager.getPluginMessageBundle(getClass().getName(), "/message/BuildNumber");
        return resourceBundle.getString("buildNumber");
    }

    @Override
    public String getDescription() {
        return getClass().getPackage().getImplementationTitle();
    }

    @Override
    public void webService(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
        try {
            if (WorkflowUtil.isCurrentUserAnonymous()) {
                throw new ApiException(HttpServletResponse.SC_UNAUTHORIZED, "Login required");
            }

            AppDefinition appDefinition = AppUtil.getCurrentAppDefinition();
            ApplicationContext applicationContext = AppUtil.getApplicationContext();
            AppService appService = (AppService) applicationContext.getBean("appService");

            final String appId = appDefinition.getAppId();
            final Long appVersion = appDefinition.getVersion();
            final String username = WorkflowUtil.getCurrentUsername();
            final String token = generateRandomToken(DIGITS);
            final Map<String, String> workflowVariables = Collections.singletonMap(VARIABLE_TOKEN, token);
            final FormData formData = new FormData();
            final String processDefId = appService.getWorkflowProcessForApp(appId, appVersion.toString(), PROCESS_OTP).getId();
            final PackageActivityForm packageActivityForm = appService.viewStartProcessForm(appId, appVersion.toString(), processDefId, formData, "");
            final Form form = packageActivityForm.getForm();
            formData.addRequestParameterValues(AssignmentCompleteButton.DEFAULT_ID, new String[]{"true"});
            formData.addRequestParameterValues(FormUtil.getElementParameterName(form) + "_SUBMITTED", new String[]{""});

            Element elementToken = FormUtil.findElement(FIELD_TOKEN, form, formData);
            if (elementToken != null) {
                final String parameterName = FormUtil.getElementParameterName(elementToken);
                formData.addRequestParameterValues(parameterName, new String[]{token});
            }

            Element elementUsername = FormUtil.findElement(FIELD_USERNAME, form, formData);
            if (elementUsername != null) {
                final String parameterName = FormUtil.getElementParameterName(elementUsername);
                formData.addRequestParameterValues(parameterName, new String[]{username});
            }

            formData.setDoValidation(true);

            WorkflowProcessResult processResult = appService.submitFormToStartProcess(appId, appVersion.toString(), processDefId, formData, workflowVariables, null, null);
            if (!formData.getFormErrors().isEmpty()) {
                final String message = formData.getFormErrors().entrySet().stream()
                        .findFirst()
                        .map(e -> "Field [" + e.getKey() + "] error [" + e.getValue() + "]")
                        .orElse("Validation error");
                throw new ApiException(HttpServletResponse.SC_BAD_REQUEST, message);
            }

            if (processResult == null) {
                throw new ApiException(HttpServletResponse.SC_BAD_REQUEST, "Error generating OTP");
            }

            servletResponse.setStatus(HttpServletResponse.SC_CREATED);

        } catch (ApiException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(e.getErrorCode(), e.getMessage());
        }
    }
}
