package com.kinnara.kecakplugins.digitalsignature.binder;

import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import org.bouncycastle.operator.OperatorCreationException;
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
import org.joget.workflow.model.service.WorkflowManager;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Stream;

public class DigitalSignElementBinder extends FormBinder implements FormStoreBinder, PKCS12Utils {
    /**
     * Inject digital certificate
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
            final String filename = getPdfFileName(element, formData);

            final File pdfFile = FileUtil.getFile(filename, element, primaryKey);
            if (!pdfFile.exists()) {
                LogUtil.warn(getClass().getName(), "File named [" + filename + "] not found");
                return rowSet;
            }

            final String userFullName = WorkflowUtil.getCurrentUserFullName();
            final String username = WorkflowUtil.getCurrentUsername();

            boolean isSigned = isSigned(pdfFile, userFullName);
            boolean override = overrideSignature();

            boolean toSign = false;
            if (!isSigned) {
                toSign = true;
            } else if (override) {
                eraseSignature(pdfFile, userFullName);
                toSign = true;
            }

            if (toSign) {
                final char[] password = getPassword();
                final File keystoreFolder = new File(ResourceUtils.getURL(PATH_USER_CERTIFICATE + "/" + username).getPath());
                if (!keystoreFolder.exists()) {
                    keystoreFolder.mkdir();
                }

                final Optional<File> optUserKeystore = optLatestKeystore(keystoreFolder, USER_KEYSTORE);
                final File userKeystore;
                if (optUserKeystore.map(File::exists).orElse(false)) {
                    userKeystore = optUserKeystore.get();
                } else {
                    userKeystore = getPathCertificateName(keystoreFolder, USER_KEYSTORE);
                    generateUserKey(userKeystore, password, userFullName);
                }

                signPdf(userKeystore, pdfFile, userFullName, getReason(formData), getOrganization(), useTimeStamp(), getTsaUrl(), getTsaUsername(), getTsaPassword());
            }
        } catch (IOException | DigitalCertificateException | ParseException |
                 GeneralSecurityException | OperatorCreationException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
            formData.addFormError(getPropertyString(FormUtil.PROPERTY_ID), e.getMessage());
        }

        return rowSet;
    }

    @Override
    public String getName() {
        return "Digital Signature Binder";
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
        return AppUtil.readPluginResource(getClass().getName(), "/properties/DigitalSignElementBinder.json", null, true, "/message/DigitalSignature");
    }

    protected String getPdfFileName(Element element, FormData formData) throws DigitalCertificateException {
        return Optional.of(formData)
                .map(fd -> fd.getLoadBinderData(element))
                .map(Collection::stream)
                .orElseGet(Stream::empty)
                .findFirst()
                .map(r -> {
                    final String elementId = element.getPropertyString(FormUtil.PROPERTY_ID);
                    return r.getProperty(elementId);
                })
                .orElseThrow(() -> new DigitalCertificateException("File not found"));
    }

    /**
     * Experimental features, currently disabled because corrupting the PDF file
     *
     * @return
     */
    protected boolean overrideSignature() {
//        return "true".equalsIgnoreCase(getPropertyString("override"));
        return false;
    }

    protected String getReason(FormData formData) throws DigitalCertificateException {
        final String propValue = getPropertyString("reason");
        if (!propValue.isEmpty()) {
            return propValue;
        }

        WorkflowManager wm = (WorkflowManager) WorkflowUtil.getApplicationContext().getBean("workflowManager");
        return Optional.of(formData)
                .map(FormData::getActivityId)
                .map(wm::getActivityById)
                .map(WorkflowActivity::getName)
                .orElse("");
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
    protected void generateUserKey(File userKeystore, char[] pass, String userFullname) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, OperatorCreationException, ParseException, UnrecoverableKeyException, DigitalCertificateException {
        KeyPair generatedKeyPair = generateKeyPair();
        String subjectDn = getDn(userFullname, getOrganizationalUnit().replace(",", " "), getOrganization().replace(",", " "), getLocality().replace(",", " "), getStateOrProvince().replace(",", " "), getCountry().replace(",", " "));
        generatePKCS12(userKeystore, pass, generatedKeyPair, subjectDn, false);
    }

    protected boolean useTimeStamp() {
        return "true".equalsIgnoreCase(getPropertyString("useTimeStamp"));
    }

    protected String getTsaUrl() {
        return getPropertyString("tsaUrl");
    }


    protected String getTsaUsername() {
        return getPropertyString("tsaUsername");
    }

    protected String getTsaPassword() {
        return getPropertyString("tsaPassword");
    }
}
