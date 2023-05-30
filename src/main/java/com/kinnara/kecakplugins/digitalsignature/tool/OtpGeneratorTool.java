package com.kinnara.kecakplugins.digitalsignature.tool;

import com.kinnara.kecakplugins.digitalsignature.util.OtpUtil;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.dao.FormDataDao;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.model.FormRowSet;
import org.joget.plugin.base.DefaultApplicationPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.workflow.model.WorkflowAssignment;
import org.joget.workflow.model.WorkflowProcess;
import org.joget.workflow.model.service.WorkflowManager;
import org.joget.workflow.util.WorkflowUtil;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;

/**
 * @author aristo
 * <p>
 * Generate random password
 */
public class OtpGeneratorTool extends DefaultApplicationPlugin implements OtpUtil {
    @Override
    public String getName() {
        return "Digital Signature Generate OTP";
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
    public Object execute(Map props) {
        executeAuditTrail("execute", props);

        final PluginManager pluginManager = (PluginManager) props.get("pluginManager");
        final WorkflowManager workflowManager = (WorkflowManager) pluginManager.getBean("workflowManager");
        final WorkflowAssignment workflowAssignment = (WorkflowAssignment) props.get("workflowAssignment");
        final FormDataDao formDataDao = (FormDataDao) pluginManager.getBean("formDataDao");
        final AppDefinition appDefinition = (AppDefinition) props.get("appDef");
        final WorkflowAssignment wfAssignment = (WorkflowAssignment) props.get("workflowAssignment");
        final WorkflowProcess process = workflowManager.getProcess(wfAssignment.getProcessDefId());
        final String token = generateRandomToken(DIGITS);

        final Collection<String> usernames = WorkflowUtil.getAssignmentUsers(process.getPackageId(), wfAssignment.getProcessDefId(), wfAssignment.getProcessId(), wfAssignment.getProcessVersion(), wfAssignment.getActivityId(), "", PARTICIPANT_OTP);
        Optional.ofNullable(generateForm(appDefinition, FORM_OTP))
                .ifPresent(form -> usernames.forEach(username -> {
                    final FormRow row = new FormRow();
                    row.put(FIELD_TOKEN, token);
                    row.put(FIELD_USERNAME, username);

                    final FormRowSet rowSet = new FormRowSet();
                    rowSet.add(row);

                    formDataDao.saveOrUpdate(form, rowSet);
                }));

        workflowManager.processVariable(workflowAssignment.getProcessId(), VARIABLE_TOKEN, token);

        return null;
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
        return null;
    }
}
