package com.kinnara.kecakplugins.digitalsignature.webapi;

import com.google.zxing.WriterException;
import com.kinnara.kecakplugins.digitalsignature.util.PdfUtil;
import com.kinnara.kecakplugins.digitalsignature.util.Unclutter;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.kecak.apps.exception.ApiException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ResourceBundle;

public class GetQrCodeApi extends ExtDefaultPlugin implements PluginWebSupport, Unclutter, PdfUtil {
    @Override
    public String getName() {
        return "Get QR Core API";
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
    public void webService(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        try {
            final String content = getParameter(httpServletRequest, "content");
            httpServletResponse.setContentType("image/png");

            final OutputStream os = httpServletResponse.getOutputStream();
            writeQrCodeToStream(content, os);
        } catch (ApiException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            httpServletResponse.sendError(e.getErrorCode(), e.getMessage());
        } catch (WriterException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            httpServletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
}
