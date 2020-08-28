package com.kinnara.kecakplugins.digitalsignature.exception;

import javax.servlet.http.HttpServletResponse;

public class RestApiException extends Exception {
    private final int errorCode;

    public RestApiException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public RestApiException(int errorCode, Throwable cause) {
        super(cause);
        this.errorCode = errorCode;
    }

    public RestApiException(String message) {
        this(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
    }

    public RestApiException(Throwable cause) {
        this(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, cause);
    }

    public int getErrorCode() {
        return errorCode;
    }
}
