package com.kinnara.kecakplugins.digitalsignature.webapi;

import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import com.kinnarastudio.commons.Try;
import org.bouncycastle.operator.OperatorCreationException;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.FileStore;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.util.WorkflowUtil;
import org.kecak.apps.exception.ApiException;
import org.springframework.util.ResourceUtils;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.ResourceBundle;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class SignApi extends ExtDefaultPlugin implements PluginWebSupport, PKCS12Utils {
    public static String ZIP_NAME = "signedPDFBy";
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
            if (!"POST".equalsIgnoreCase(method)) {
                throw new ApiException(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Unsupported method [" + method + "]");
            }

            if (WorkflowUtil.isCurrentUserAnonymous()) {
                throw new ApiException(HttpServletResponse.SC_UNAUTHORIZED, "Login required");
            }

            // TODO sign pdf document

            LogUtil.info(getClass().getName(), "Executing Rest API [" + servletRequest.getRequestURI() + "] in method [" + servletRequest.getMethod() + "] contentType [" + servletRequest.getContentType() + "] as [" + WorkflowUtil.getCurrentUsername() + "]");

            final String userFullName = WorkflowUtil.getCurrentUserFullName();
            servletResponse.setContentType("Content-type: text/zip");
            servletResponse.setHeader("Content-Disposition",
                    "attachment; filename="+ZIP_NAME+userFullName+".zip");

            ServletOutputStream out = servletResponse.getOutputStream();
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(out));

            FileStore.getFileMap().values().stream()

                    // unbox deep stream
                    .flatMap(Arrays::stream)

                    // store to temp folder (app_tempfile)
                    .map(FileManager::storeFile)

                    // construct path to file
                    .map(path -> FileManager.getBaseDirectory() + "/" + path)

                    // assign file object
                    .map(File::new)

                    // make sure file exists
                    .filter(File::exists)

                    // collect stream as array of File
                    .forEach(Try.onConsumer(pdfFile -> {
                        // get / generate keystore
                        String username = WorkflowUtil.getCurrentUsername();

                        URL baseUrl = ResourceUtils.getURL(PATH_USER_CERTIFICATE + "/" + username);
                        final File folder = new File(baseUrl.getPath());
                        final File userKeystoreFile = getLatestKeystore(folder, "certificate." + KEYSTORE_TYPE);

                        char[] pass = getPassword();
                        if (!userKeystoreFile.exists()) {
                            generateUserKey(userKeystoreFile, pass, userFullName);
                        }

                        //sign PDF
                        signPdf(userKeystoreFile, pdfFile, userFullName, "Sign", DEFAULT_DN_ORG);
                        final String name = pdfFile.getName();

                        //write file to output stream
                        zos.putNextEntry(new ZipEntry(name));
                        FileInputStream fis = new FileInputStream(pdfFile);
                        BufferedInputStream bis = new BufferedInputStream(fis);

                        int data = 0;
                        while ((data = bis.read()) != -1) {
                            zos.write(data);
                        }
                        bis.close();
                        zos.closeEntry();
                    }));

            zos.close();
        } catch (ApiException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(e.getErrorCode(), e.getMessage());
        }
    }

    public void generateUserKey(File certificateFile, char[] pass, String userFullname) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, OperatorCreationException, ParseException, UnrecoverableKeyException, DigitalCertificateException {
        KeyPair generatedKeyPair = generateKeyPair();
        String subjectDn = getDn(userFullname, DEFAULT_DN_ORG_UNIT, DEFAULT_DN_ORG, DEFAULT_DN_LOCALITY, DEFAULT_DN_STATE, DEFAULT_DN_COUNTRY);
        generatePKCS12(certificateFile, pass, generatedKeyPair, subjectDn, false);
    }
}
