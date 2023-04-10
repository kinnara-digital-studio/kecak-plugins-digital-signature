package com.kinnara.kecakplugins.digitalsignature.exception;

import com.itextpdf.signatures.VerificationException;

import java.util.List;

public class DigitalCertificateVerificationException extends Exception {
    private final List<VerificationException> errors;

    public DigitalCertificateVerificationException(List<VerificationException> errors) {
        super();
        this.errors = errors;
    }


    public List<VerificationException> getErrors() {
        return errors;
    }
}
