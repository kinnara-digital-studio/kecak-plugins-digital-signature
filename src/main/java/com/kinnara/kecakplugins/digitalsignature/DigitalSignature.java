package com.kinnara.kecakplugins.digitalsignature;

import org.joget.apps.app.dao.FormDefinitionDao;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.model.FormDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.dao.FormDataDao;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FileDownloadSecurity;
import org.joget.apps.form.model.Form;
import org.joget.apps.form.model.FormBuilderPaletteElement;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormService;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

@Deprecated
public class DigitalSignature extends Element implements FormBuilderPaletteElement, FileDownloadSecurity {
	@Override
	public String renderTemplate(FormData formData, Map dataModel) {
		String template = "digitalSignature.ftl";

		String formDefId = getPropertyString("formDefId");
		String signatureId = getPropertyString("fileField");
		String username = getPropertyString("username");

		String thisFormDefId = "";
		Form form = FormUtil.findRootForm(this);
		if (form != null) {
			thisFormDefId = form.getPropertyString(FormUtil.PROPERTY_ID);
		}
		
		String appId = "";
		String appVersion = "";

		AppDefinition appDef = AppUtil.getCurrentAppDefinition();
		if (appDef != null) {
			appId = appDef.getId();
			appVersion = appDef.getVersion().toString();
		}

		String primaryKeyValue = getPrimaryKeyValue(formData);

		String value = FormUtil.getElementPropertyValue(this, formData);
		if(value!=null) {
			String encodedFileName = value;
			try {
				encodedFileName = URLEncoder.encode(value, "UTF8").replaceAll("\\+", "%20");
			} catch (UnsupportedEncodingException ex) {
				// ignore
			}
			if(encodedFileName!=null && !encodedFileName.equals("")) {
				String fileLocation = FileUtil.getUploadPath(this, primaryKeyValue) + "/" + encodedFileName;
				File file = new File(fileLocation);
				if(file.exists()) {
					String filePath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + thisFormDefId + "/" + primaryKeyValue + "/" + encodedFileName + ".";
					dataModel.put("pdfFile", filePath);
				}else {
					String filePath;
					try {
						filePath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + thisFormDefId + "/" + primaryKeyValue + "/" + URLEncoder.encode(value,"UTF-8") + ".";
						dataModel.put("pdfFile", filePath);
					} catch (UnsupportedEncodingException e) {
						LogUtil.error(this.getClassName(), e, e.getMessage());
					}
					
				}
			}else {
				String filePath;
				try {
					filePath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + thisFormDefId + "/" + primaryKeyValue + "/" + URLEncoder.encode(value,"UTF-8") + ".";
					dataModel.put("pdfFile", filePath);
				} catch (UnsupportedEncodingException e) {
					LogUtil.error(this.getClassName(), e, e.getMessage());
				}
				
			}
		}else{
			dataModel.put("pdfFile", "");
		}

		//Ambil signature nya
		ApplicationContext appContext = AppUtil.getApplicationContext();
		FormDataDao formDataDao = (FormDataDao)appContext.getBean("formDataDao");
		WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
		String currentUser = wum.getCurrentUsername();
		
		Form formMaster = generateForm(formDefId);
		LogUtil.info(this.getClass().getName(), "USERNAME FIELD: "+username);
		LogUtil.info(this.getClass().getName(), "USERNAME: "+currentUser);
		LogUtil.info(this.getClass().getName(), "FORM: "+formMaster.getLabel());
		String masterPK = formDataDao.findPrimaryKey(formMaster, username, currentUser);
		LogUtil.info(this.getClass().getName(), "Primary Key: "+masterPK);
		FormRow row = formDataDao.load(formMaster, masterPK);
		LogUtil.info(this.getClass().getName(), row.getProperty(signatureId));
		dataModel.put("className", getClassName());
		try {
			String signaturePath = "/web/client/app/" + appId + "/" + appVersion + "/form/download/" + formDefId + "/" + masterPK + "/" + URLEncoder.encode(row.getProperty(signatureId),"UTF-8") + ".";
			dataModel.put("signatureFile", signaturePath);
		} catch (UnsupportedEncodingException e) {
			LogUtil.error(this.getClassName(), e, e.getMessage());;
		}
		String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
		return html;
	}

	protected Form generateForm(String formDefId) {
		// proceed without cache
		ApplicationContext appContext = AppUtil.getApplicationContext();
		FormService formService = (FormService) appContext.getBean("formService");
		FormDefinitionDao formDefinitionDao = (FormDefinitionDao)appContext.getBean("formDefinitionDao");

		AppDefinition appDef = AppUtil.getCurrentAppDefinition();

		if (appDef != null && formDefId != null && !formDefId.isEmpty()) {
			FormDefinition formDef = formDefinitionDao.loadById(formDefId, appDef);
			if (formDef != null) {
				String json = formDef.getJson();
				LogUtil.info(this.getClass().getName(), "FORM JSON: "+json);
				return (Form) formService.createElementFromJson(json);
			}
		}
		return null;
	}


	@Override
	public String getFormBuilderCategory() {
		return "Kecak";
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
		return "<label class='label' style='position:absolute;top:10px;left:10px;'>Digital Signature</label><div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'><span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:70px;align:center;'>PDF</span><div>";
	}

	@Override
	public String getName() {
		return "(Deprecated) Digital Signature";
	}

	@Override
	public String getVersion() {
		return getClass().getPackage().getImplementationVersion();
	}

	@Override
	public String getDescription() {
		return getClass().getPackage().getImplementationTitle();
	}

	@Override
	public String getLabel() {
		return this.getName();
	}

	@Override
	public String getClassName() {
		return getClass().getName();
	}

	@Override
	public String getPropertyOptions() {
		return AppUtil.readPluginResource(getClass().getName(), "/properties/digitalSignature.json", null, true, "/message/digitalSignature");
	}

	@Override
	public boolean isDownloadAllowed(Map requestParameters) {
		// TODO Auto-generated method stub
		return true;
	}
}
