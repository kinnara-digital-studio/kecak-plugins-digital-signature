package com.kinnara.kecakplugins.digitalsignature.util;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.workflow.model.WorkflowAssignment;
import org.springframework.web.client.RestClientException;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLContext;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

public interface PdfUtils {
    boolean getHtmlEmbed(WorkflowAssignment assignment);

    String getPdfUrl(WorkflowAssignment assignment);

    /**
     * Get HTTP request
     *
     * @param assignment
     * @param url
     * @return
     * @throws RestClientException
     */
    default HttpUriRequest getHttpRequest(WorkflowAssignment assignment, String url) {
        final HttpRequestBase request = new HttpGet(url);
        return request;
    }

    /**
     * Get HTTP Client
     *
     * @return
     * @throws RestClientException
     */
    default HttpClient getHttpClient() {
        try {
            SSLContext sslContext = new SSLContextBuilder()
                    .loadTrustMaterial(null, (certificate, authType) -> true).build();
            return HttpClients.custom().setSSLContext(sslContext)
                    .setSSLHostnameVerifier(new NoopHostnameVerifier())
                    .build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            return HttpClientBuilder.create().build();
        }
    }

    /**
     * Get content type from response
     *
     * @param response
     * @return
     * @throws RestClientException
     */
    default String getResponseContentType(@Nonnull HttpResponse response) {
        return Optional.of(response)
                .map(HttpResponse::getEntity)
                .map(HttpEntity::getContentType)
                .map(Header::getValue)
                .orElse("");
    }

    /**
     * Reads a specified InputStream, returning its contents in a byte array
     * @param in
     * @return
     * @throws IOException
     */
    default byte[] readInputStream(InputStream in) throws IOException {
        byte[] fileContent;
        try(ByteArrayOutputStream out = new ByteArrayOutputStream();
            BufferedInputStream bin = new BufferedInputStream(in)) {
            int len;
            byte[] buffer = new byte[4096];
            while ((len = bin.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
            out.flush();
            fileContent = out.toByteArray();
            return fileContent;
        }
    }

    default String getSrc(WorkflowAssignment workflowAssignment) {
        if(getHtmlEmbed(workflowAssignment)) {
            try {
                return AppUtil.processHashVariable(getEncodedSrc(workflowAssignment), workflowAssignment, null, null);
            } catch (IOException e) {
                LogUtil.error(getClass().getName(), e, e.getMessage());
                return "";
            }
        } else {
            return getPdfUrl(workflowAssignment);
        }
    }

    default String getEncodedSrc(WorkflowAssignment workflowAssignment) throws IOException {
        HttpClient client = getHttpClient();
        HttpUriRequest request = getHttpRequest(workflowAssignment, getPdfUrl(workflowAssignment));
        HttpResponse response = client.execute(request);
        String contentType = getResponseContentType(response);
        if(!contentType.contains("application/pdf")) {
            LogUtil.warn(getClass().getName(), "Content ["+contentType+"] is not PDF");
            return "/plugin/" + getClass().getName() +"/images/pdf-logo.png";
        }

        try(InputStream inputStream = response.getEntity().getContent()) {
            byte[] bytes = readInputStream(inputStream);
            String base64Encoded = Base64.getEncoder().encodeToString(bytes);
            return "data:application/pdf;base64, " + base64Encoded;
        }
    }
}
