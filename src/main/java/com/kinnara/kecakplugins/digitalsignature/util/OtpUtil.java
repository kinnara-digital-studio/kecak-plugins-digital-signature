package com.kinnara.kecakplugins.digitalsignature.util;

import org.joget.apps.app.dao.FormDefinitionDao;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.model.FormDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.dao.FormDataDao;
import org.joget.apps.form.model.Form;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.service.FormService;
import org.springframework.context.ApplicationContext;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Stream;

public interface OtpUtil extends AuditTrailUtil{

    String PROCESS_OTP = "otp";

    String PARTICIPANT_OTP = "otpUser";
    String VARIABLE_TOKEN = "token";
    String FORM_OTP = "otp";

    String FIELD_USERNAME = "username";
    String FIELD_TOKEN = "token";

    int DETAULT_TIMELIMIT = 20;
    int DIGITS = 6;

    default String generateRandomToken(int digits) {
        Random rand = new Random();
        return String.format("%0" + digits + "d", rand.nextInt((int) Math.pow(10, digits)));
    }

    default Form generateForm(AppDefinition appDef, String formDefId) {
        // proceed without cache
        ApplicationContext appContext = AppUtil.getApplicationContext();
        FormService formService = (FormService) appContext.getBean("formService");

        if (appDef != null && formDefId != null && !formDefId.isEmpty()) {
            FormDefinitionDao formDefinitionDao =
                    (FormDefinitionDao) AppUtil.getApplicationContext().getBean("formDefinitionDao");

            FormDefinition formDef = formDefinitionDao.loadById(formDefId, appDef);
            if (formDef != null) {
                String json = formDef.getJson();
                Form form = (Form) formService.createElementFromJson(json);
                return form;
            }
        }
        return null;
    }

    /**
     *
     * @param username
     */
    default void purgeOtpHistory(String username) {
        ApplicationContext applicationContext = AppUtil.getApplicationContext();
        AppDefinition appDefinition = AppUtil.getCurrentAppDefinition();
        FormDataDao formDataDao = (FormDataDao) applicationContext.getBean("formDataDao");

        final Form form = generateForm(appDefinition, FORM_OTP);
        final String[] ids = Optional.ofNullable(formDataDao.find(form, "where e.customProperties.username = ?", new String[]{username}, null, null, null, null))
                .map(Collection::stream)
                .orElseGet(Stream::empty)
                .map(FormRow::getId)
                .toArray(String[]::new);

        formDataDao.delete(form, ids);
    }

    /**
     *
     * @param username
     * @param token
     * @param limitInMinutes    put 0 to check against the latest token
     * @return
     */
    default boolean validateOtp(String username, String token, int limitInMinutes) {
        ApplicationContext applicationContext = AppUtil.getApplicationContext();
        AppDefinition appDefinition = AppUtil.getCurrentAppDefinition();
        FormDataDao formDataDao = (FormDataDao) applicationContext.getBean("formDataDao");

        final Form form = generateForm(appDefinition, FORM_OTP);

        if(limitInMinutes > 0) {

            final Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.MINUTE, -limitInMinutes);

            final Date aWhileAgo = calendar.getTime();
            final String strAWhileAgo = new SimpleDateFormat("yyyy-MM-dd HH:ss").format(aWhileAgo);

            return Optional.ofNullable(formDataDao.count(form, "where e.customProperties.username = ? AND e.customProperties.token = ? AND e.customProperties.dateCreated >= ?", new String[]{username, token, strAWhileAgo}))
                    .map(l -> l > 0)
                    .orElse(false);
        }

        // get the latest
        else {
            return Optional.ofNullable(formDataDao.find(form, "where e.customProperties.username = ? AND e.customProperties.token = ?", new String[]{username, token}, "dateCreated",true, null, 1))
                    .map(Collection::stream)
                    .orElseGet(Stream::empty)
                    .anyMatch(r -> true);
        }
    }
}
