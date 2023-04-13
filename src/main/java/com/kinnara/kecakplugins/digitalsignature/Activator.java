package com.kinnara.kecakplugins.digitalsignature;

import java.util.ArrayList;
import java.util.Collection;

import com.kinnara.kecakplugins.digitalsignature.binder.DigitalSignElementBinder;
import com.kinnara.kecakplugins.digitalsignature.element.PdfViewerElement;
import com.kinnara.kecakplugins.digitalsignature.menu.DigitalSignatureVerifyMenu;
import com.kinnara.kecakplugins.digitalsignature.tool.OtpGeneratorTool;
import com.kinnara.kecakplugins.digitalsignature.validator.OtpValidator;
import com.kinnara.kecakplugins.digitalsignature.webapi.*;
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
        registrationList.add(context.registerService(GetOtpApi.class.getName(), new GetOtpApi(), null));
        registrationList.add(context.registerService(SignApi.class.getName(), new SignApi(), null));
        registrationList.add(context.registerService(VerifyApi.class.getName(), new VerifyApi(), null));
        registrationList.add(context.registerService(DigitalCertificateFileUpload.class.getName(), new DigitalCertificateFileUpload(), null));
        registrationList.add(context.registerService(DigitalSignElementBinder.class.getName(), new DigitalSignElementBinder(), null));
        registrationList.add(context.registerService(RootCertificateStoreBinder.class.getName(), new RootCertificateStoreBinder(), null));
        registrationList.add(context.registerService(PdfViewerElement.class.getName(), new PdfViewerElement(), null));
        registrationList.add(context.registerService(OtpValidator.class.getName(), new OtpValidator(), null));
        registrationList.add(context.registerService(DigitalSignatureVerifyMenu.class.getName(), new DigitalSignatureVerifyMenu(), null));
        registrationList.add(context.registerService(OtpGeneratorTool.class.getName(), new OtpGeneratorTool(), null));
    }

    public void stop(BundleContext context) {
        for (ServiceRegistration registration : registrationList) {
            registration.unregister();
        }
    }
}