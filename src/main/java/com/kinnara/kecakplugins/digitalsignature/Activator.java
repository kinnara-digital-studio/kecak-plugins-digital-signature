package com.kinnara.kecakplugins.digitalsignature;

import java.util.ArrayList;
import java.util.Collection;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

public class Activator implements BundleActivator {

    protected Collection<ServiceRegistration> registrationList;

    public void start(BundleContext context) {
        registrationList = new ArrayList<ServiceRegistration>();

        //Register plugin here
        registrationList.add(context.registerService(GetSignatureApi.class.getName(), new GetSignatureApi(), null));
        registrationList.add(context.registerService(DigitalSignature.class.getName(), new DigitalSignature(), null));
        registrationList.add(context.registerService(DigitalCertificateFileUpload.class.getName(), new DigitalCertificateFileUpload(), null));
        registrationList.add(context.registerService(DigitalSignatureElement.class.getName(), new DigitalSignatureElement(), null));
//        registrationList.add(context.registerService(QRElement.class.getName(), new QRElement(), null));
    }

    public void stop(BundleContext context) {
        for (ServiceRegistration registration : registrationList) {
            registration.unregister();
        }
    }
}