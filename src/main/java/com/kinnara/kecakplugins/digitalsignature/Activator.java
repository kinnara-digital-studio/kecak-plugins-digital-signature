package com.kinnara.kecakplugins.digitalsignature;

import java.util.ArrayList;
import java.util.Collection;

import com.kinnara.kecakplugins.digitalsignature.binder.DigitalSignatureElementBinder;
import com.kinnara.kecakplugins.digitalsignature.element.DigitalSignatureElement;
import com.kinnara.kecakplugins.digitalsignature.menu.DigitalSignatureVerifyMenu;
import com.kinnara.kecakplugins.digitalsignature.webapi.GetQrCodeApi;
import com.kinnara.kecakplugins.digitalsignature.webapi.GetSignatureApi;
import com.kinnara.kecakplugins.digitalsignature.webapi.SignApi;
import com.kinnara.kecakplugins.digitalsignature.webapi.VerifyApi;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

public class Activator implements BundleActivator {

    protected Collection<ServiceRegistration> registrationList;

    public void start(BundleContext context) {
        registrationList = new ArrayList<ServiceRegistration>();

        //Register plugin here
        registrationList.add(context.registerService(GetSignatureApi.class.getName(), new GetSignatureApi(), null));
        registrationList.add(context.registerService(GetQrCodeApi.class.getName(), new GetQrCodeApi(), null));
        registrationList.add(context.registerService(SignApi.class.getName(), new SignApi(), null));
        registrationList.add(context.registerService(VerifyApi.class.getName(), new VerifyApi(), null));
        registrationList.add(context.registerService(DigitalCertificateFileUpload.class.getName(), new DigitalCertificateFileUpload(), null));
        registrationList.add(context.registerService(DigitalSignatureElementBinder.class.getName(), new DigitalSignatureElementBinder(), null));
        registrationList.add(context.registerService(RootCertificateStoreBinder.class.getName(), new RootCertificateStoreBinder(), null));
        registrationList.add(context.registerService(DigitalSignatureElement.class.getName(), new DigitalSignatureElement(), null));
        registrationList.add(context.registerService(DigitalSignatureVerifyMenu.class.getName(), new DigitalSignatureVerifyMenu(), null));
    }

    public void stop(BundleContext context) {
        for (ServiceRegistration registration : registrationList) {
            registration.unregister();
        }
    }
}