package com.kinnara.kecakplugins.digitalsignature.exception;

import com.itextpdf.signatures.VerificationException;

import java.util.Collections;
import java.util.List;

public class DigitalCertificateVerificationException extends Exception {
    private final List<VerificationException> errors;

    public DigitalCertificateVerificationException(List<VerificationException> errors) {
        super(errors.get(0));
        this.errors = errors;
    }

    public DigitalCertificateVerificationException(String message) {
        super(message);
        this.errors = Collections.emptyList();
    }


    public List<VerificationException> getErrors() {
        return errors;
    }
}
