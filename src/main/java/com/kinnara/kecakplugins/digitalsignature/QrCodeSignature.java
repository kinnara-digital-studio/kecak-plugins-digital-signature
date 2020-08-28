package com.kinnara.kecakplugins.digitalsignature;

import com.google.zxing.WriterException;
import com.kinnara.kecakplugins.digitalsignature.exception.RestApiException;
import com.kinnara.kecakplugins.digitalsignature.util.QrGenerator;
import com.kinnara.kecakplugins.digitalsignature.util.Unclutter;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.model.PackageDefinition;
import org.joget.apps.app.model.PluginDefaultProperties;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.plugin.base.DefaultApplicationPlugin;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.plugin.property.service.PropertyUtil;
import org.joget.workflow.model.WorkflowActivity;
import org.joget.workflow.model.WorkflowProcess;
import org.joget.workflow.model.WorkflowVariable;
import org.joget.workflow.model.service.WorkflowManager;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.context.ApplicationContext;

import javax.annotation.Nonnull;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class QrCodeSignature extends DefaultApplicationPlugin implements PluginWebSupport, QrGenerator, Unclutter {
    private final static DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");

    @Override
    public String getName() {
        return "QR Code Signature";
    }

    @Override
    public String getVersion() {
        return getClass().getPackage().getImplementationVersion();
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
        JSONArray jsonActivityOptionsProperties = getGetterMethods(WorkflowActivity.class).stream()
                .map(throwableFunction(s -> {
                    JSONObject jsonObject = new JSONObject();
                    jsonObject.put("value", s);
                    jsonObject.put("label", decapitalize(s.replaceAll("^get", "")));
                    return jsonObject;
                }))
                .collect(JSONArray::new, JSONArray::put, (result, src) -> jsonStream(src).forEach(throwableConsumer(result::put)));

        JSONArray jsonWorkflowVariables = getWorkflowVariables(AppUtil.getCurrentAppDefinition()).stream()
                .map(throwableFunction(v -> {
                    JSONObject jsonObject = new JSONObject();
                    jsonObject.put("value", v);
                    jsonObject.put("label", v);
                    return jsonObject;
                }))
                .collect(JSONArray::new, JSONArray::put, (result, src) -> jsonStream(src).forEach(throwableConsumer(result::put)));

        String[] args = new String[] {
                jsonActivityOptionsProperties.toString().replaceAll("\"", "'"),
                jsonWorkflowVariables.toString().replaceAll("\"", "'")
        };
        return AppUtil.readPluginResource(getClassName(), "/properties/QrCodeSignature.json", args, false, "/messages/QrCode");
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String action = getOptionalParameter(request, "action", "");

            // verify QR
            if("verify".equals(action)) {
                verifyQr(request, response);
            }

            // generate QR
            else {
                generateQr(request, response);
            }

        } catch (RestApiException e) {
            LogUtil.error(getClassName(), e, e.getMessage());
            response.sendError(e.getErrorCode(), e.getMessage());
        }
    }

    private String getRequiredParameter(HttpServletRequest request, String parameterName) throws RestApiException {
        return Optional.of(parameterName)
                .map(request::getParameter)
                .orElseThrow(() -> new RestApiException(HttpServletResponse.SC_BAD_REQUEST, "Parameter ["+parameterName+" is not supplied]"));
    }

    private String getOptionalParameter(HttpServletRequest request, String parameterName, String defaultValue) {
        return Optional.of(parameterName)
                .map(request::getParameter)
                .orElse(defaultValue);
    }

    @Override
    public Object execute(Map map) {
        return null;
    }

    private Map<String, Object> getConfiguration() throws RestApiException {
        AppDefinition appDefinition = AppUtil.getCurrentAppDefinition();
        return appDefinition
                .getPluginDefaultPropertiesList()
                .stream()
                .filter(p -> p.getId().equals(getClassName()))
                .findFirst()
                .map(PluginDefaultProperties::getPluginProperties)
                .map(PropertyUtil::getPropertiesValueFromJson)
                .orElseThrow(() -> new RestApiException(HttpServletResponse.SC_FORBIDDEN, "Missing configuration"));
    }

    private String getHost() throws RestApiException {
        return Optional.of("host")
                .map(getConfiguration()::get)
                .map(String::valueOf)
                .map(s -> AppUtil.processHashVariable(s, null, null, null))
                .orElseThrow(() -> new RestApiException(HttpServletResponse.SC_FORBIDDEN, "Missing [host] configuration"));
    }

    private String getVerificationUrl() throws RestApiException {
        return Optional.of("verificationUrl")
                .map(getConfiguration()::get)
                .map(String::valueOf)
                .map(s -> AppUtil.processHashVariable(s, null, null, null))
                .orElseThrow(() -> new RestApiException(HttpServletResponse.SC_FORBIDDEN, "Missing verificationUrl configuration"));
    }

    /**
     * Get property "workflowVariables"
     *
     * @return
     * @throws RestApiException
     */
    private List<String> getWorkflowVariables() throws RestApiException {
        return Optional.of("workflowVariables")
                .map(getConfiguration()::get)
                .map(String::valueOf)
                .map(s -> s.split(";"))
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(this::isNotEmpty)
                .map(s -> AppUtil.processHashVariable(s, null, null, null))
                .collect(Collectors.toList());
    }

    /**
     * Generate QR Code
     *
     * @param request
     * @param response
     * @throws RestApiException
     */
    private void generateQr(@Nonnull final HttpServletRequest request, @Nonnull final HttpServletResponse response) throws RestApiException {
        AppDefinition appDefinition = AppUtil.getCurrentAppDefinition();
        ApplicationContext applicationContext = AppUtil.getApplicationContext();
        WorkflowManager workflowManager = (WorkflowManager) applicationContext.getBean("workflowManager");

        String activityId = getRequiredParameter(request, "activityId");
        WorkflowActivity info = workflowManager.getRunningActivityInfo(activityId);

        int width = Integer.parseInt(getOptionalParameter(request, "width", "256"));
        int height = Integer.parseInt(getOptionalParameter(request, "height", "256"));

        String host = getHost().replaceAll("/$", "");
        String appId = appDefinition.getAppId();
        long appVersion = appDefinition.getVersion();

        JSONObject jsonContent = new JSONObject();
        try {
            getActivityProperties()
                    .stream()
                    .map(throwableFunction(s -> info.getClass().getMethod(s)))
                    .forEach(throwableConsumer(method -> Optional.of(method.getName())
                            .map(s -> s.replaceAll("^get", ""))
                            .map(this::decapitalize)
                            .ifPresent(throwableConsumer(s -> jsonContent.put(s, method.invoke(info))))));

            Collection<WorkflowVariable> variables = Optional.of(activityId)
                    .map(workflowManager::getActivityVariableList)
                    .orElseGet(Collections::emptyList);

            for(final String variable : getWorkflowVariables()) {
                String value = variables
                        .stream()
                        .filter(wVar -> Optional.of(wVar)
                                .map(WorkflowVariable::getName)
                                .map(variable::equals)
                                .orElse(false))
                        .findAny()
                        .map(WorkflowVariable::getVal)
                        .map(String::valueOf)
                        .orElse("");

                jsonContent.put(variable, value);
            }
        } catch (JSONException e) {
            throw new RestApiException(e);
        }


        try {
            String content = host + "/web/json/app/" + appId + "/" + appVersion + "/plugin/" + QrCodeSignature.class.getName() + "/service?action=verify&data=" + URLEncoder.encode(SecurityUtil.encrypt(jsonContent.toString()), "UTF-8");
            response.setContentType("image/png");
            writeQrCodeToStream(content, width, height, response.getOutputStream());
        } catch (WriterException | IOException e) {
            throw new RestApiException(e);
        }
    }

    /**
     * Verify QR Code
     *
     * @param request
     * @param response
     * @throws RestApiException
     */
    private void verifyQr(@Nonnull final HttpServletRequest request, @Nonnull final HttpServletResponse response) throws RestApiException {
        String data = SecurityUtil.decrypt(getRequiredParameter(request, "data"));
        JSONObject jsonContent = Optional.of(data)
                .map(throwableFunction(JSONObject::new))
                .orElseThrow(() -> new RestApiException(HttpServletResponse.SC_BAD_REQUEST, "Unable to verify data ["+data+"]"));

        try {
            String verificationUrl = getVerificationUrl().replaceAll("\\$", "");
            if(verificationUrl.isEmpty()) {
                response.setContentType("application/json");
                response.getWriter().write(jsonContent.toString());
            } else {
                String parameterData = jsonStream(jsonContent)
                        .map(throwableFunction(key -> String.format("%s=%s", key, URLEncoder.encode(jsonContent.getString(key), "UTF-8"))))
                        .collect(Collectors.joining("&"));

                final Pattern p = Pattern.compile("https?://.+\\?.+=,*");
                Matcher m = p.matcher(verificationUrl);

                response.sendRedirect(verificationUrl + (m.find() ? "&" : "?") + parameterData);
            }
        } catch (IOException e) {
            throw new RestApiException(e);
        }
    }

    private String decapitalize(String string) {
        if (string == null || string.length() == 0) {
            return string;
        }

        char[] c = string.toCharArray();
        c[0] = Character.toLowerCase(c[0]);

        return new String(c);
    }

    /**
     * Get configuration property "activityProperties"
     *
     * @return
     * @throws RestApiException
     */
    private List<String> getActivityProperties() throws RestApiException {
        return Optional.of("activityProperties")
                .map(getConfiguration()::get)
                .map(String::valueOf)
                .map(s -> s.split(";"))
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(this::isNotEmpty)
                .collect(Collectors.toList());
    }

    /**
     * Get getter methods
     *
     * @param cls
     * @return
     */
    private Set<String> getGetterMethods(Class cls) {
        return Optional.of(cls.getName())
                .map(throwableFunction(Class::forName))
                .map(Class::getMethods)
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(m -> m.getParameterCount() == 0)
                .map(throwableFunction(Method::getName))
                .filter(s -> s.startsWith("get"))
                .collect(Collectors.toSet());
    }

    private Set<String> getWorkflowVariables(AppDefinition appDefinition) {
        ApplicationContext applicationContext = AppUtil.getApplicationContext();
        WorkflowManager workflowManager = (WorkflowManager) applicationContext.getBean("workflowManager");
        return Optional.of(appDefinition)
                .map(AppDefinition::getPackageDefinition)
                .map(PackageDefinition::getId)
                .map(workflowManager::getProcessList)
                .map(Collection::stream)
                .orElseGet(Stream::empty)
                .map(WorkflowProcess::getId)
                .map(workflowManager::getProcessVariableDefinitionList)
                .flatMap(Collection::stream)
                .map(WorkflowVariable::getId)
                .collect(Collectors.toSet());
    }
}
