package com.kinnara.kecakplugins.digitalsignature;

import com.google.zxing.WriterException;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfSigner;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import com.kinnara.kecakplugins.digitalsignature.util.PdfUtil;
import com.kinnara.kecakplugins.digitalsignature.util.Unclutter;
import com.kinnara.kecakplugins.digitalsignature.webapi.GetQrCodeApi;
import com.kinnara.kecakplugins.digitalsignature.webapi.GetSignatureApi;
import com.kinnarastudio.commons.Try;
import org.bouncycastle.operator.OperatorCreationException;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;
import org.joget.directory.model.Department;
import org.joget.directory.model.Employment;
import org.joget.directory.model.Organization;
import org.joget.directory.model.User;
import org.joget.directory.model.service.ExtDirectoryManager;
import org.joget.plugin.base.PluginManager;
import org.joget.workflow.model.WorkflowActivity;
import org.joget.workflow.model.WorkflowAssignment;
import org.joget.workflow.model.service.WorkflowManager;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.net.URL;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Display PDF content
 */
public class DigitalSignatureElement extends Element implements FormBuilderPaletteElement, FileDownloadSecurity, Unclutter, PdfUtil, PKCS12Utils {
    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        String template = "DigitalSignatureElement.ftl";

        final String primaryKeyValue = getPrimaryKeyValue(formData);
        final String value = FormUtil.getElementPropertyValue(this, formData);
        String encodedFileName = value;
        try {
            encodedFileName = URLEncoder.encode(value, "UTF8").replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException ignored) {
        }

        final AppDefinition appDef = AppUtil.getCurrentAppDefinition();
        final Form form = FormUtil.findRootForm(this);

        if (appDef != null && form != null) {
            final String appId = appDef.getId();
            final String appVersion = appDef.getVersion().toString();
            final String formDefId = form.getPropertyString(FormUtil.PROPERTY_ID);
            final String pdfPath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + formDefId + "/" + primaryKeyValue + "/" + encodedFileName + ".";
            dataModel.put("pdfFile", pdfPath);
        }

        dataModel.put("className", getClassName());

        final String stampFile;
        if(isSignature()) {
            stampFile = "/web/json/plugin/" + GetSignatureApi.class.getName() + "/service";
        } else if(isQrCode()) {
            stampFile = "/web/json/plugin/" + GetQrCodeApi.class.getName() + "/service?content=foo";
        } else {
            stampFile = "";
        }

        dataModel.put("stampFile", stampFile);
        String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
        return html;
    }

    @Override
    public FormRowSet formatData(FormData formData) {
        try {
            final String primaryKey = formData.getPrimaryKeyValue();
            final String filename = getPdfFileName(formData);

            final File pdfFile = FileUtil.getFile(filename, this, primaryKey);
            if (!pdfFile.exists()) {
                LogUtil.warn(getClass().getName(), "File named [" + filename + "] not found");
                return null;
            }

            if(isSignature() || isQrCode()) {

                final String stampPositions = FormUtil.getElementPropertyValue(this, formData);
                final int page = getPagePosition(stampPositions);
                final float top = getTopPosition(stampPositions);
                final float left = getLeftPosition(stampPositions);
                final float scaleX = getScaleXPosition(stampPositions);
                final float scaleY = getScaleYPosition(stampPositions);

                // signature
                if (isSignature()) {
                    final File signatureFile = getSignature();
                    stampPdf(pdfFile, signatureFile, page, left, top, scaleX, scaleY, Math.toRadians(0));
                }

                // QR code
                else if (isQrCode()) {
                    try (final ByteArrayOutputStream os = new ByteArrayOutputStream()) {
                        writeQrCodeToStream(getQrContent(formData), os);

                        final byte[] qrCode = os.toByteArray();
                        stampPdf(pdfFile, qrCode, page, left, top, scaleX, scaleY, Math.toRadians(0));
                    }
                }
            }


            final String userFullName = WorkflowUtil.getCurrentUserFullName();
            final String username = WorkflowUtil.getCurrentUsername();

            boolean isSigned = isSigned(pdfFile, userFullName);
            boolean override = overrideSignature();

            boolean toSign = false;
            if(!isSigned) {
                toSign = true;
            } else if(override) {
                eraseSignature(pdfFile, userFullName);
                toSign = true;
            }

            if(toSign) {
                final char[] password = getPassword();
                final File keystoreFolder = new File(ResourceUtils.getURL(PATH_CERTIFICATE + "/" + username).getPath());
                if (!keystoreFolder.exists()) {
                    keystoreFolder.mkdir();
                }

                final File userKeystore = getLatestKeystore(keystoreFolder, "certificate." + KEYSTORE_TYPE);
                if (!userKeystore.exists()) {
                    generateUserKey(userKeystore, password, userFullName);
                }

                final Certificate[] certificateChain = getCertificateChain(userKeystore, password);
                final PrivateKey privateKey = getPrivateKey(userKeystore, password);
                final Provider securityProvider = getSecurityProvider();

                startSign(userKeystore, pdfFile, userFullName, getReason(formData), getOrganization());
                signPdf(userFullName, pdfFile, pdfFile, certificateChain, privateKey, DigestAlgorithms.SHA256, securityProvider.getName(), PdfSigner.CryptoStandard.CMS,
                        getReason(formData), getOrganization(), null, null, null, 0);
            }
        } catch (IOException | DigitalCertificateException | WriterException | ParseException |
                 GeneralSecurityException | OperatorCreationException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());

            formData.addFormError(getPropertyString(FormUtil.PROPERTY_ID), e.getMessage());
        }

        // do not store anything in database
        return null;
    }

    protected String getReason(FormData formData) throws DigitalCertificateException {
        final String propValue = getPropertyString("reason");
        if(!propValue.isEmpty()) {
            return propValue;
        }

        WorkflowManager wm = (WorkflowManager) WorkflowUtil.getApplicationContext().getBean("workflowManager");
        return Optional.of(formData)
                .map(FormData::getActivityId)
                .map(wm::getActivityById)
                .map(WorkflowActivity::getName)
                .orElse("");
    }

    protected String getQrContent(FormData formData) {
        WorkflowManager workflowManager = (WorkflowManager) AppUtil.getApplicationContext().getBean("workflowManager");
        final WorkflowAssignment assignment = workflowManager.getAssignment(formData.getActivityId());
        return AppUtil.processHashVariable(getPropertyString("qrContent"), assignment, null, null);
    }

    protected boolean isSignature() {
        return "signature".equalsIgnoreCase(getPropertyString("stampType"));
    }

    protected boolean isQrCode() {
        return "qrCode".equalsIgnoreCase(getPropertyString("stampType"));
    }

    protected String getPdfFileName(FormData formData) throws DigitalCertificateException {
        return Optional.of(formData).map(fd -> fd.getLoadBinderData(this)).map(Collection::stream).orElseGet(Stream::empty).findFirst().map(r -> r.getProperty(getPropertyString(FormUtil.PROPERTY_ID))).orElseThrow(() -> new DigitalCertificateException("File not found"));
    }

    protected int getPagePosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 0, Integer::parseInt);
    }

    protected float getTopPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 1, Float::parseFloat);
    }


    protected float getLeftPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 2, Float::parseFloat);
    }

    protected float getScaleXPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 4, Float::parseFloat);
    }

    protected float getScaleYPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 3, Float::parseFloat);
    }

    protected <T> T getPositionIndex(String positions, int index, Function<String, T> parser) throws DigitalCertificateException {
        return Optional.of(positions).map(s -> s.split(";")).map(Arrays::stream).orElseGet(Stream::empty).skip(index).findFirst().map(parser).orElseThrow(() -> new DigitalCertificateException("Invalid positions [" + positions + "] at index [" + index + "]"));
    }

    @Override
    public String getFormBuilderCategory() {
        return "Digital Signature";
    }

    @Override
    public int getFormBuilderPosition() {
        return 200;
    }

    @Override
    public String getFormBuilderIcon() {
        return "/plugin/org.joget.apps.form.lib.TextField/images/textField_icon.gif";
    }

    @Override
    public String getFormBuilderTemplate() {
        return "<label class='label' style='position:absolute;top:10px;left:10px;'>" + getName() + "</label><div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'><span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:70px;align:center;'>PDF</span><div>";
    }

    @Override
    public String getName() {
        return "PDF Viewer";
    }

    @Override
    public String getVersion() {
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        ResourceBundle resourceBundle = pluginManager.getPluginMessageBundle(getClassName(), "/message/BuildNumber");
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
        return AppUtil.readPluginResource(getClass().getName(), "/properties/DigitalSignatureElement.json", null, true, "/message/DigitalSignature");
    }

    @Override
    public boolean isDownloadAllowed(Map requestParameters) {
        return true;
    }

    protected String getStateOrProvince() {
        return getPropertyString("stateOrProvince");
    }

    protected String getCountry() {
        return getPropertyString("country");
    }

    protected String getLocality() {
        return getPropertyString("locality");
    }

    protected String getOrganizationalUnit() {
        final String propValue = getPropertyString("organizationalUnit");
        if (!propValue.isEmpty()) {
            return propValue;
        }

        final ExtDirectoryManager directoryManager = (ExtDirectoryManager) AppUtil.getApplicationContext().getBean("directoryManager");

        final String username = WorkflowUtil.getCurrentUsername();
        final User user = directoryManager.getUserById(username);
        final Set<Employment> employments = (Set<Employment>) user.getEmployments();

        return Optional.ofNullable(employments)
                .map(Collection::stream)
                .orElseGet(Stream::empty)
                .map(Employment::getDepartment)
                .filter(Objects::nonNull)
                .map(Department::getName)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse("");
    }

    protected String getOrganization() {
        final String propValue = getPropertyString("organization");
        if (!propValue.isEmpty()) {
            return propValue;
        }

        final ExtDirectoryManager directoryManager = (ExtDirectoryManager) AppUtil.getApplicationContext().getBean("directoryManager");

        final String orgId = WorkflowUtil.getCurrentUserOrgId();
        return Optional.of(orgId)
                .map(directoryManager::getOrganization)
                .map(Organization::getName)
                .orElse("");
    }

    /**
     *
     * @param userKeystore
     * @param pass
     * @param userFullname
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws IOException
     * @throws OperatorCreationException
     * @throws ParseException
     * @throws UnrecoverableKeyException
     * @throws DigitalCertificateException
     */
    public void generateUserKey(File userKeystore, char[] pass, String userFullname) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, OperatorCreationException, ParseException, UnrecoverableKeyException, DigitalCertificateException {
        KeyPair generatedKeyPair = generateKeyPair();
        String subjectDn = getDn(userFullname, getOrganizationalUnit(), getOrganization(), getLocality(), getStateOrProvince(), getCountry());
        generatePKCS12(userKeystore, pass, generatedKeyPair, subjectDn, false);
    }

    protected boolean overrideSignature() {
        return getPropertyString("override").equalsIgnoreCase("true");
    }
}
