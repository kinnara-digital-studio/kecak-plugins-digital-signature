package com.kinnara.kecakplugins.digitalsignature.validator;

import com.kinnara.kecakplugins.digitalsignature.util.OtpUtil;
import com.kinnarastudio.commons.Try;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.model.FormValidator;
import org.joget.apps.form.service.FormUtil;
import org.joget.plugin.base.PluginManager;
import org.joget.workflow.util.WorkflowUtil;

import java.util.Arrays;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.stream.Stream;

/**
 * OTP Validator
 *
 * Validate OTP
 */
public class OtpValidator extends FormValidator implements OtpUtil {
    @Override
    public boolean validate(Element element, FormData formData, String[] values) {
        final String username = WorkflowUtil.getCurrentUsername();
        final String token = Optional.ofNullable(values)
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .findFirst()
                .map(String::trim)
                .orElse("");
        final int timeOut = getTimeOut();
        if(validateOtp(username, token, timeOut)) {
            return true;
        }

        final String id = element.getPropertyString(FormUtil.PROPERTY_ID);
        formData.addFormError(id, getErrorMessage());

        return false;
    }

    protected int getTimeOut() {
        return Optional.of(getPropertyString("timeout"))
                .filter(s -> !s.isEmpty())
                .map(Try.onFunction(Integer::parseInt))
                .orElse(DETAULT_TIMELIMIT);
    }

    protected String getErrorMessage() {
        return getPropertyString("errorMessage");
    }

    @Override
    public String getName() {
        return "Digital Signature OTP Validator";
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
    public String getLabel() {
        return getName();
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        final String[] args = { String.valueOf(DETAULT_TIMELIMIT) };
        return AppUtil.readPluginResource(getClass().getName(), "/properties/OtpValidator.json", args, false);
    }
}
