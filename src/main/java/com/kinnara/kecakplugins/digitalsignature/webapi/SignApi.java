package com.kinnara.kecakplugins.digitalsignature.webapi;

import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import com.kinnarastudio.commons.Try;
import org.bouncycastle.operator.OperatorCreationException;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.service.FileUtil;
import org.joget.commons.util.FileManager;
import org.joget.commons.util.FileStore;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.util.WorkflowUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.kecak.apps.exception.ApiException;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.stream.Stream;

public class SignApi extends ExtDefaultPlugin implements PluginWebSupport, PKCS12Utils {
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

//                    // collect stream as array of File
//                    .toArray(File[]::new);
                    .forEach(Try.onConsumer(pdfFile -> {

//                        LogUtil.info(getClass().getName(), "file :" + pdfFile.getAbsolutePath());
//                        LogUtil.info(getClass().getName(), "email :" + userFullName);
//
//                        // get / generate keystore
//                        File userKeystoreFile = new File("input_file.pdf");
//                        generateUserKey(userKeystoreFile, getPassword(), userFullName);
//                        startSign(userKeystoreFile, pdfFile, userFullName, "Sign", DEFAULT_DN_ORG);

                        servletResponse.setContentType("application/pdf");

                        final String name = pdfFile.getName();
                        servletResponse.setHeader("Content-Disposition", "attachment; filename=" + name + "; filename*=UTF-8''" + name);

                        byte[] bytes = Files.readAllBytes(pdfFile.toPath());
                        servletResponse.getOutputStream().write(bytes);
                    }));

//            for (File pdfFile : filesToSign) {
//
////            String fileToSign = servletRequest.getParameter("file");
//                String userFullname = servletRequest.getHeader("email");
//
//
//                LogUtil.info(getClass().getName(), "file :" + pdfFile.getAbsolutePath());
//                LogUtil.info(getClass().getName(), "email :" + userFullname);
//
////                File pdfFile = new File(fileToSign);
//                File userKeystoreFile = new File("input_file.pdf");
//
//                //SIGN PDF
//                generateUserKey(userKeystoreFile, getPassword(), userFullname);
//                startSign(userKeystoreFile, pdfFile, userFullname, "Sign", DEFAULT_DN_ORG);
//            }

//            final JSONObject responseBody = new JSONObject();
////            responseBody.put("signedFile", pdfFile);
//            responseBody.put("status", false);
//            responseBody.put("message", "UNDER DEVELOPMENT");
//
//            servletResponse.getWriter().write(responseBody.toString());
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

    protected String[] getTempFilePath(String elementId) {
        return Optional.of(elementId)
                .map(Try.onFunction(FileStore::getFiles))
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .map(FileManager::storeFile)
                .toArray(String[]::new);
    }
}
