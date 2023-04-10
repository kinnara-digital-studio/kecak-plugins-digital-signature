package com.kinnara.kecakplugins.digitalsignature.webapi;

import com.itextpdf.bouncycastle.cert.ocsp.BasicOCSPRespBC;
import com.itextpdf.commons.bouncycastle.cert.ocsp.IBasicOCSPResp;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.*;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateVerificationException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import com.kinnara.kecakplugins.digitalsignature.util.Unclutter;
import com.kinnarastudio.commons.Try;
import org.javatuples.Pair;
import org.joget.apps.app.service.AppUtil;
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Stream;

public class VerifyApi extends ExtDefaultPlugin implements PluginWebSupport, Unclutter, PKCS12Utils {

    @Override
    public String getName() {
        return "Verify API";
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

            LogUtil.info(getClass().getName(), "Executing Rest API [" + servletRequest.getRequestURI() + "] in method [" + servletRequest.getMethod() + "] contentType [" + servletRequest.getContentType() + "] as [" + WorkflowUtil.getCurrentUsername() + "]");

            FileStore.getFileMap().values().stream()

                    // unbox deep stream
                    .flatMap(Arrays::stream)

                    // store to temp folder (app_tempfile)
                    .map(FileManager::storeFile)

                    .findFirst()

                    // construct path to file
                    .map(path -> FileManager.getBaseDirectory() + "/" + path)

                    // assign file object
                    .map(File::new)

                    // make sure file exists
                    .filter(File::exists)
                    .map(Try.onFunction(pdfFile -> verifySignatures(pdfFile)))


                    //verify PDF
                    .map(Try.onFunction(this::verifySignatures))

                    // if any error is found, return empty list
                    .orElse(Collections.emptyList());

            final JSONObject responseBody = new JSONObject();
            responseBody.put("Data", data);

//            responseBody.put("message", "UNDER DEVELOPMENT");
            servletResponse.setStatus(HttpServletResponse.SC_OK);
            servletResponse.getWriter().write(responseBody.toString());
        } catch (ApiException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(e.getErrorCode(), e.getMessage());
        } catch (JSONException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    public List<Map<String, Object>> verifySignatures(File pdfFile) throws IOException, GeneralSecurityException, DigitalCertificateException, ApiException, DigitalCertificateVerificationException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(pdfFile));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();

        final List<Map<String, Object>> data = new ArrayList<>();
        for (String name : names) {
            LogUtil.info(getClass().getName(), "===== " + name + " =====");

            final Map<String, Object> signatureData = verifySignature(signUtil, name);
            data.add(signatureData);
        }
        return data;
    }

    /**
     * @param signUtil
     * @param name
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws DigitalCertificateException
     */
    public Map<String, Object> verifySignature(SignatureUtil signUtil, String name) throws GeneralSecurityException,
            IOException, DigitalCertificateException, DigitalCertificateVerificationException {
        PdfPKCS7 pkcs7 = getSignatureData(signUtil, name);
        Certificate[] certs = pkcs7.getSignCertificateChain();

        // Timestamp is a secure source of signature creation time,
        // because it's based on Time Stamping Authority service.
        final Calendar cal;

        // If there is no timestamp, use the current date
        if (TimestampConstants.UNDEFINED_TIMESTAMP_DATE == pkcs7.getTimeStampDate()) {
            cal = Calendar.getInstance();
        } else {
            cal = pkcs7.getTimeStampDate();
        }

        // Check if the certificate chain, presented in the PDF, can be verified against
        // the created key store.

        //get list of root
        File rootFolder = new File(PATH_ROOT);

        final Map<String, Object> signatureData = new HashMap<>();
        signatureData.put("signatureName", name);

        final List<VerificationException> finalError = new ArrayList<>();

        File rootKeystore = Optional.ofNullable(rootFolder.listFiles())
                .map(Arrays::stream)
                .orElse(Stream.empty())
                .filter(f -> f.getName().endsWith("_" + ROOT_KEYSTORE))
                .sorted(Comparator.comparing(File::getName))
                .map(Try.onFunction(file -> {
                    try(InputStream rootKeystoreInputStream = Files.newInputStream(file.toPath())) {
                        char[] password = getPassword();
                        final KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
                        ks.load(rootKeystoreInputStream, password);
                        return Pair.with(file, ks);
                    }
                }))
                .filter(Objects::nonNull)
                .map(Try.onFunction(p -> {
                    final List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, p.getValue1(), cal);

                    finalError.clear();
                    finalError.addAll(errors);

                    return Pair.with(p.getValue0(), errors);
                }))
                .filter(Objects::nonNull)
                .filter(p -> p.getValue1().isEmpty())
                .map(Pair::getValue0)
                .findFirst()
                .orElseThrow(() -> new DigitalCertificateVerificationException(finalError));

        LogUtil.info(getClass().getName(), "Verified using root [" + rootKeystore.getName() +"]");

        // Find out if certificates were valid on the signing date, and if they are still valid today
        final List<Map<String, String>> rootList = new ArrayList<>();
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            LogUtil.info(getClass().getName(), "=== Certificate " + i + " ===");
            rootList.add(showCertificateInfo(cert, cal.getTime()));
        }
        signatureData.put("rootData", rootList);

        // Take the signing certificate
        X509Certificate signCert = (X509Certificate) certs[0];

        // Take the certificate of the issuer of that certificate (or null if it was self-signed).
        X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate) certs[1] : null);

        LogUtil.info(getClass().getName(), "=== Checking validity of the document at the time of signing ===");
        checkRevocation(pkcs7, signCert, issuerCert, cal.getTime());

        LogUtil.info(getClass().getName(), "=== Checking validity of the document today ===");
        checkRevocation(pkcs7, signCert, issuerCert, new Date());

        return signatureData;
    }


    public PdfPKCS7 getSignatureData(SignatureUtil signUtil, String name) throws GeneralSecurityException {
        PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);

        LogUtil.info(getClass().getName(), "Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
        LogUtil.info(getClass().getName(), "Document revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
        LogUtil.info(getClass().getName(), "Integrity check OK? " + pkcs7.verifySignatureIntegrityAndAuthenticity());

        return pkcs7;
    }

    public void checkRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, Date date)
            throws GeneralSecurityException, IOException {
        List<IBasicOCSPResp> ocsps = new ArrayList<>();
        if (pkcs7.getOcsp() != null) {
            ocsps.add(new BasicOCSPRespBC(((BasicOCSPRespBC) pkcs7.getOcsp()).getBasicOCSPResp()));
        }

//        CertificateVerifier verifier = new CertificateVerifier( );

        // Check if the OCSP responses in the list were valid for the certificate on a specific date.
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, ocsps);
        List<VerificationOK> verification = ocspVerifier.verify(signCert, issuerCert, date);

        // If that list is empty, we can't verify using OCSP, and we need to look for CRLs.
        if (verification.size() == 0) {
            List<X509CRL> crls = new ArrayList<X509CRL>();
            if (pkcs7.getCRLs() != null) {
                for (CRL crl : pkcs7.getCRLs()) {
                    crls.add((X509CRL) crl);
                }
            }

            // Check if the CRLs in the list were valid on a specific date.
            CRLVerifier crlVerifier = new CRLVerifier(null, crls);
            verification.addAll(crlVerifier.verify(signCert, issuerCert, date));
        }

        if (verification.size() == 0) {
            LogUtil.info(getClass().getName(), "The signing certificate couldn't be verified");
        } else {
            for (VerificationOK v : verification) {
                LogUtil.info(getClass().getName(), v.toString());
            }
        }
    }

    public Map<String, String> showCertificateInfo(X509Certificate cert, Date signDate) {
        LogUtil.info(getClass().getName(), "Issuer: " + cert.getIssuerDN());
        LogUtil.info(getClass().getName(), "Subject: " + cert.getSubjectDN());
        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
        date_format.setTimeZone(TimeZone.getTimeZone("Universal"));
        LogUtil.info(getClass().getName(), "Valid from: " + date_format.format(cert.getNotBefore()));
        LogUtil.info(getClass().getName(), "Valid to: " + date_format.format(cert.getNotAfter()));

        final Map<String, String> rootData = new HashMap<>();
        rootData.put("issuer", cert.getIssuerDN().toString());
        rootData.put("subject", cert.getSubjectDN().toString());
        rootData.put("validFrom", date_format.format(cert.getNotBefore()));
        rootData.put("validTo", date_format.format(cert.getNotAfter()));

        // Check if a certificate was valid on the signing date
        try {
            cert.checkValidity(signDate);
            LogUtil.info(getClass().getName(), "The certificate was valid at the time of signing.");
            rootData.put("certificateDetail", "The certificate was valid at the time of signing.");
        } catch (CertificateExpiredException e) {
            LogUtil.info(getClass().getName(), "The certificate was expired at the time of signing.");
            rootData.put("certificateDetail", "The certificate was expired at the time of signing.");
        } catch (CertificateNotYetValidException e) {
            LogUtil.info(getClass().getName(), "The certificate wasn't valid yet at the time of signing.");
            rootData.put("certificateDetail", "The certificate asn't valid yet at the time of signing.");
        }

        // Check if a certificate is still valid now
        try {
            cert.checkValidity();
            LogUtil.info(getClass().getName(), "The certificate is still valid.");
            rootData.put("certificateStatus", "Valid");
        } catch (CertificateExpiredException e) {
            LogUtil.info(getClass().getName(), "The certificate has expired.");
            rootData.put("certificateStatus", "Expired");
        } catch (CertificateNotYetValidException e) {
            LogUtil.info(getClass().getName(), "The certificate isn't valid yet.");
            rootData.put("certificateStatus", "Invalid");
        }
        return rootData;
    }
}



// 20230102 -> err
// 20220102 -> err
// 20190102 -> err