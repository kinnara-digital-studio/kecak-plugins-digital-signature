import com.kinnara.kecakplugins.digitalsignature.DigitalCertificateFileUpload;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Test {
    @org.junit.Test
    public void generateKey() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, OperatorCreationException {
        DigitalCertificateFileUpload obj = new DigitalCertificateFileUpload() {
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
        obj.generateKey(file, "password".toCharArray(), "Aristo Keren");

        System.out.println(file.getAbsolutePath());

        Assert.assertTrue(file.exists());
    }
}
