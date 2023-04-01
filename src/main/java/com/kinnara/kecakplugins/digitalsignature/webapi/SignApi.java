package com.kinnara.kecakplugins.digitalsignature.webapi;

import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.util.WorkflowUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.kecak.apps.exception.ApiException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ResourceBundle;

public class SignApi extends ExtDefaultPlugin implements PluginWebSupport {
    @Override
    public String getName() {
        return "Sign API";
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
            final String method = servletRequest.getMethod();
            if(!"POST".equalsIgnoreCase(method)) {
                throw new ApiException(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Unsupported method [" + method + "]");
            }

            if(WorkflowUtil.isCurrentUserAnonymous()) {
                throw new ApiException(HttpServletResponse.SC_UNAUTHORIZED, "Login required");
            }

            // TODO sign pdf document

            final JSONObject responseBody = new JSONObject();
            responseBody.put("status", false);
            responseBody.put("message", "UNDER DEVELOPMENT");

            servletResponse.getWriter().write(responseBody.toString());
        } catch (ApiException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(e.getErrorCode(), e.getMessage());
        } catch (JSONException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
}
