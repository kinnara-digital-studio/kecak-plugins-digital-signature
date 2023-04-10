package com.kinnara.kecakplugins.digitalsignature.binder;

import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.plugin.base.PluginManager;

import java.util.ResourceBundle;

public class DigitalSignatureElementBinder extends FormBinder implements FormLoadBinder, FormStoreBinder {
    @Override
    public FormRowSet load(Element element, String primaryKey, FormData formData) {
        return null;
    }
    @Override
    public FormRowSet store(Element element, FormRowSet rowSet, FormData formData) {
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
        return "";
    }

}
