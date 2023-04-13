package com.kinnara.kecakplugins.digitalsignature.element;

import com.google.zxing.WriterException;
import com.kinnara.kecakplugins.digitalsignature.binder.DigitalSignElementBinder;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import com.kinnara.kecakplugins.digitalsignature.util.PdfUtil;
import com.kinnara.kecakplugins.digitalsignature.util.Unclutter;
import com.kinnara.kecakplugins.digitalsignature.webapi.GetQrCodeApi;
import com.kinnara.kecakplugins.digitalsignature.webapi.GetSignatureApi;
import com.kinnarastudio.commons.Try;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.PluginManager;
import org.joget.workflow.model.WorkflowAssignment;
import org.joget.workflow.model.service.WorkflowManager;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Display PDF content
 *
 * Stamping will be handled in method {@link #store(Element, FormRowSet, FormData)} while
 * signing will be handled by {@link #secondaryBinder}
 */
public class PdfViewerElement extends Element implements FormBuilderPaletteElement, FileDownloadSecurity, FormStoreElementBinder, Unclutter, PdfUtil, PKCS12Utils {
    // secondary binder will be executed after embedded store binder
    private FormStoreBinder secondaryBinder = null;

    @Override
    public String renderTemplate(FormData formData, Map dataModel) {
        String template = "PdfViewerElement.ftl";

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
        if (isSignature()) {
            stampFile = "/web/json/plugin/" + GetSignatureApi.class.getName() + "/service";
        } else if (isQrCode()) {
            stampFile = "/web/json/plugin/" + GetQrCodeApi.class.getName() + "/service?content=foo";
        } else {
            stampFile = "";
        }

        dataModel.put("stampFile", stampFile);
        String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
        return html;
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
        return getPositionIndex(positions, 0, Try.onFunction(Integer::parseInt, (RuntimeException e) -> 1));
    }

    protected float getTopPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 1, Try.onFunction(Float::parseFloat, (RuntimeException e) -> 0f));
    }


    protected float getLeftPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 2, Try.onFunction(Float::parseFloat, (RuntimeException e) -> 0f));
    }

    protected float getScaleXPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 4, Try.onFunction(Float::parseFloat, (RuntimeException e) -> 1f));
    }

    protected float getScaleYPosition(String positions) throws DigitalCertificateException {
        return getPositionIndex(positions, 3, Try.onFunction(Float::parseFloat, (RuntimeException e) -> 1f));
    }

    protected <T> T getPositionIndex(String positions, int index, Function<String, T> parser) throws DigitalCertificateException {
        return Optional.of(positions)
                .map(s -> s.split(";"))
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .skip(index)
                .findFirst()
                .map(parser)
                .orElseThrow(() -> new DigitalCertificateException("Invalid positions [" + positions + "] at index [" + index + "]"));
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
        final String[] args = new String[]{ DigitalSignElementBinder.class.getName() };
        return AppUtil.readPluginResource(getClass().getName(), "/properties/PdfViewerElement.json", args, true, "/message/DigitalSignature");
    }

    @Override
    public boolean isDownloadAllowed(Map requestParameters) {
        return true;
    }

    /**
     * Setup inline store binder {@link #store(Element, FormRowSet, FormData)}
     * and {@link #secondaryBinder}
     *
     * @param storeBinderFromProperties
     */
    @Override
    public void setStoreBinder(FormStoreBinder storeBinderFromProperties) {
        super.setStoreBinder(this); // inline store binder

        // secondary store is set with store binder in properties
        this.secondaryBinder = storeBinderFromProperties;
    }

    /**
     * Stamp current pdf using signature of QR code
     *
     * @param element
     * @param rowSet
     * @param formData
     * @return
     */
    @Override
    public FormRowSet store(Element element, FormRowSet rowSet, FormData formData) {
        try {
            final String primaryKey = formData.getPrimaryKeyValue();
            final String filename = getPdfFileName(formData);

            final File pdfFile = FileUtil.getFile(filename, this, primaryKey);
            if (!pdfFile.exists()) {
                LogUtil.warn(getClass().getName(), "File named [" + filename + "] not found");
                return null;
            }

            if (isSignature() || isQrCode()) {
                try {
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
                } catch (IOException e) {
                    LogUtil.error(getClass().getName(), e, e.getMessage());
                }
            }
        } catch (IOException | DigitalCertificateException | WriterException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            formData.addFormError(getPropertyString(FormUtil.PROPERTY_ID), e.getMessage());
        }

        return secondaryBinder == null ? rowSet : secondaryBinder.store(element, rowSet, formData);
    }
}
