package com.kinnara.kecakplugins.digitalsignature.element;

import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import com.kinnara.kecakplugins.digitalsignature.util.PKCS12Utils;
import com.kinnarastudio.commons.Try;
import com.kinnarastudio.commons.jsonstream.JSONStream;
import org.bouncycastle.operator.OperatorCreationException;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.FileManager;
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
import org.json.JSONArray;
import org.json.JSONException;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Stream;


/**
 * Upload and sign file
 */
public class FileUpload extends org.joget.apps.form.lib.FileUpload implements PKCS12Utils {

    public final static String PATH_FORMUPLOADS = "wflow/app_formuploads/";

    public FormRowSet formatData(FormData formData) {
        String userFullname = WorkflowUtil.getCurrentUserFullName();

        //get uploaded file from app_temp
        String pdfFilePath = FormUtil.getElementPropertyValue(this, formData);
        File pdfFile = new File(FileManager.getBaseDirectory() + "/" + pdfFilePath);

        try {
            if (pdfFile.exists()) {
                pdfFile = FileManager.getFileByPath(pdfFilePath);
            } else {
                //update current file
                Form form = FormUtil.findRootForm(this);
                URL fileUrl = ResourceUtils.getURL(PATH_FORMUPLOADS + form.getPropertyString(FormUtil.PROPERTY_ID) + "/" + form.getPrimaryKeyValue(formData) + "/" + pdfFilePath);
                pdfFile = ResourceUtils.getFile(fileUrl.getPath());
            }
            boolean signed = isSigned(pdfFile, userFullname);
            boolean override = overrideSignature();

            boolean toSign = false;
            if (!signed) {
                toSign = true;
            } else if (override) {
                toSign = true;
                eraseSignature(pdfFile, pdfFile, userFullname);
            }

            if (toSign) {
                //get digital certificate of current user login
                String username = WorkflowUtil.getCurrentUsername();

                URL baseUrl = ResourceUtils.getURL(PATH_USER_CERTIFICATE + "/" + username);
                final File folder = new File(baseUrl.getPath());
                final Optional<File> optUserKeystoreFile = optLatestKeystore(folder, USER_KEYSTORE);
                char[] pass = getPassword();

                final File userKeystoreFile;
                if (optUserKeystoreFile.map(File::exists).orElse(false)) {
                    userKeystoreFile = optUserKeystoreFile.get();
                } else {
                    userKeystoreFile = getPathCertificateName(folder, USER_KEYSTORE);
                    generateUserKey(userKeystoreFile, pass, userFullname);
                }

                signPdf(userKeystoreFile, pdfFile, userFullname, getReason(formData),getOrganization(), useTimeStamp(), getTsaUrl(), getTsaUsername(), getTsaPassword());
                LogUtil.info(getClassName(), "Document [" + pdfFile.getName() + "] has been signed by [" + userFullname + "]");
            }

            return super.formatData(formData);
        } catch (Exception e) {
            LogUtil.error(getClassName(), e, e.getMessage());
            final String parameterName = FormUtil.getElementParameterName(this);
            formData.addFileError(parameterName, e.getMessage());
        }

        return null;
    }

    protected String getReason(FormData formData) {
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

    /**
     * @param certificateFile
     * @param pass
     * @param userFullname
     * @return keystore file
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws IOException
     * @throws OperatorCreationException
     * @throws ParseException
     * @throws UnrecoverableKeyException
     * @throws DigitalCertificateException
     */
    public void generateUserKey(File certificateFile, char[] pass, String userFullname) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, OperatorCreationException, ParseException, UnrecoverableKeyException, DigitalCertificateException {
        KeyPair generatedKeyPair = generateKeyPair();
        String subjectDn = getDn(userFullname.replace(",", " "), getOrganizationalUnit().replace(",", " "), getOrganization().replace(",", " "), getLocality().replace(",", " "), getStateOrProvince().replace(",", " "), getCountry().replace(",", " "));
        generatePKCS12(certificateFile, pass, generatedKeyPair, subjectDn, false);
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
     * Experimental features, currently disabled because corrupting the PDF file
     *
     * @return
     */
    protected boolean overrideSignature() {
//        return "true".equalsIgnoreCase(getPropertyString("override"));
        return false;
    }

    @Override
    public String getName() {
        return "File Upload";
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
    public String getFormBuilderCategory() {
        return FORM_BUILDER_CATEGORY;
    }

    @Override
    public String getPropertyOptions() {
        try {
            JSONArray currentPluginProperties = new JSONArray(AppUtil.readPluginResource(getClassName(), "/properties/DigitalCertificateFileUpload.json", null, true, "/messages/DigitalCertificate"));
            JSONArray parentPluginProperties = new JSONArray(super.getPropertyOptions());

            // merge with parent's plugin properties
            JSONStream.of(currentPluginProperties, Try.onBiFunction(JSONArray::getJSONObject))
                    .forEach(parentPluginProperties::put);

            return parentPluginProperties.toString().replace("\"", "'");
        } catch (JSONException e) {
            LogUtil.error(getClassName(), e, e.getMessage());
            return super.getPropertyOptions();
        }
    }

    protected boolean useTimeStamp() {
//        return "true".equalsIgnoreCase(getPropertyString("useTimeStamp"));
        return true;
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
