package com.kinnara.kecakplugins.digitalsignature.webapi;

import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.kecak.apps.exception.ApiException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.ResourceBundle;

public class GetTimeStampApi extends ExtDefaultPlugin implements PluginWebSupport, PKCS12Utils {
    @Override
    public String getName() {
        return "Get Timestamp API";
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
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            final String method = request.getMethod();
            if(!"POST".equalsIgnoreCase(method)) {
                throw new ApiException(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method [" + method + "] is not supported");
            }

            final String contentType = request.getContentType();
            if(!"application/timestamp-query".equalsIgnoreCase(contentType)) {
                throw new ApiException(HttpServletResponse.SC_BAD_REQUEST, "Content type [" + contentType + "] is not supported");
            }

            // read the timestamp request from the request body
            byte[] tsqBytes = getRequestBytes(request);
            byte[] tsr = getTimeStampResponse(tsqBytes);

            // write the timestamp response to the response body
            response.setContentType("application/timestamp-reply");
            response.getOutputStream().write(tsr);

        } catch (GeneralSecurityException | OperatorCreationException | TSPException | DigitalCertificateException |
                 ParseException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing timestamp request");
        } catch (ApiException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            response.sendError(e.getErrorCode(), e.getMessage());
        }
    }

    protected byte[] getRequestBytes(HttpServletRequest request) throws IOException, ApiException {
        final InputStream is = request.getInputStream();

        try(ByteArrayOutputStream os = new ByteArrayOutputStream()) {

            final byte[] buffer = new byte[1024];
            int n;
            while((n = is.read(buffer)) > 0) {
                os.write(buffer, 0, n);
            }

            final byte[] bytes = os.toByteArray();
            if(bytes.length > 0) {
                return bytes;
            } else {
                throw new ApiException(HttpServletResponse.SC_BAD_REQUEST, "Error parsing timestamp request");
            }
        }
    }
}
