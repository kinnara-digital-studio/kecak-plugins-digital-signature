package com.kinnara.kecakplugins.digitalsignature.webapi;

import com.kinnara.kecakplugins.digitalsignature.util.PdfUtil;
import com.kinnara.kecakplugins.digitalsignature.util.Unclutter;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.util.WorkflowUtil;
import org.kecak.apps.exception.ApiException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.ResourceBundle;

public class GetSignatureApi extends ExtDefaultPlugin implements PluginWebSupport, Unclutter, PdfUtil {

    @Override
    public String getName() {
        return "Get Signature API";
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
                throw new ApiException(HttpServletResponse.SC_FORBIDDEN, "Login required");
            }

            final File signatureFile = getSignature();
            if(!signatureFile.exists()) {
                throw new ApiException(HttpServletResponse.SC_NOT_FOUND, "Signature not found");
            }

            servletResponse.setContentType("image/png");
            try (final ServletOutputStream outputStream = servletResponse.getOutputStream();
                 final FileInputStream fis = new FileInputStream(signatureFile);
                 final DataInputStream dis = new DataInputStream(fis)) {

                byte[] bbuf = new byte[65536];

                // send output
                int length = 0;
                while ((length = dis.read(bbuf)) != -1) {
                    outputStream.write(bbuf, 0, length);
                }
                outputStream.flush();
            }
        } catch (ApiException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(e.getErrorCode(), e.getMessage());
        } catch (FileNotFoundException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, e.getMessage());
        }
    }
}
