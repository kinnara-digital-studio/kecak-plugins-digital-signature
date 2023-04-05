package com.kinnara.kecakplugins.digitalsignature.menu;

import org.joget.apps.app.service.AppUtil;
import org.joget.apps.userview.model.UserviewMenu;
import org.joget.plugin.base.PluginManager;
import org.springframework.context.ApplicationContext;

import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

public class DigitalSignatureVerifyMenu extends UserviewMenu {
    @Override
    public String getCategory() {
        return "Digital Signature";
    }

    @Override
    public String getIcon() {
        return null;
    }

    @Override
    public String getRenderPage() {

        final ApplicationContext appContext = AppUtil.getApplicationContext();
        final PluginManager pluginManager = (PluginManager) appContext.getBean("pluginManager");
        final Map<String, Object> dataModel = new HashMap<>();
        final String template = "/templates/DigitalSignatureVerifyMenu.ftl";
        final String label = getLabel();
        dataModel.put("className", getClassName());
        dataModel.put("label", label);
        final String htmlContent = pluginManager.getPluginFreeMarkerTemplate(dataModel, getClassName(), template, null);
        return htmlContent;
    }

    @Override
    public boolean isHomePageSupported() {
        return false;
    }

    @Override
    public String getDecoratedMenu() {
        return null;
    }

    @Override
    public String getName() {
        return getLabel();
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
        return "Verify PDF";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClass().getName(), "/properties/DigitalSignatureVerifyMenu.json", null, true, "/message/DigitalSignature");
    }
}
