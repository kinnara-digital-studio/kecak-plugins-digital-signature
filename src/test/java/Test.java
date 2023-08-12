import com.kinnara.kecakplugins.digitalsignature.element.FileUpload;
import com.kinnara.kecakplugins.digitalsignature.exception.DigitalCertificateException;
import org.bouncycastle.operator.OperatorCreationException;
import org.joget.commons.util.LogUtil;
import org.junit.Assert;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;

public class Test {
//    @org.junit.Test
    public void generateKey() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, OperatorCreationException, ParseException {
        FileUpload obj = new FileUpload() {
            @Override
            protected String getStateOrProvince() {
                return "West Java";
            }

            @Override
            protected String getOrganizationalUnit() {
                return "Developer";
            }

            @Override
            protected String getOrganization() {
                return "Kinnara Digital Studio";
            }

            @Override
            protected String getCountry() {
                return "ID";
            }
        };
        File file = File.createTempFile("cert", ".pkcs12");
        try {
            obj.generateUserKey(file, "password".toCharArray(), "Aristo Keren");
        } catch (UnrecoverableKeyException | DigitalCertificateException e) {
            LogUtil.error(getClass().getName(), e, e.getMessage());
        }

        System.out.println(file.getAbsolutePath());

        Assert.assertTrue(file.exists());
    }
}
