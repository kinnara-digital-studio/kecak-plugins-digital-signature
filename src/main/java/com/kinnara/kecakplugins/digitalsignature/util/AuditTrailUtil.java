package com.kinnara.kecakplugins.digitalsignature.util;

import org.joget.apps.app.service.AppUtil;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.util.WorkflowUtil;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

public interface AuditTrailUtil {
    default void executeAuditTrail(String methodName, Object... parameters) {
        final WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");

        final Class[] types = Optional.of(this)
                .map(Object::getClass)
                .map(Class::getMethods)
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(m -> methodName.equals(m.getName()) && Arrays.stream(m.getParameterTypes()).allMatch(Arrays.asList(parameters)::contains))
                .findFirst()
                .map(Method::getParameterTypes)
                .orElse(null);

        final HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        final String httpUrl = Optional.ofNullable(request).map(HttpServletRequest::getRequestURI).orElse("");
        final String httpMethod = Optional.ofNullable(request).map(HttpServletRequest::getMethod).orElse("");

        workflowHelper.addAuditTrail(
                this.getClass().getName(),
                methodName,
                "Rest API " + httpUrl + " method " + httpMethod,
                types,
                parameters,
                null
        );
    }
}
