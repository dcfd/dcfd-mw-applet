package ejb;

import java.security.cert.X509Certificate;
import javax.ejb.LocalBean;
import javax.ejb.Stateless;
import javax.servlet.http.HttpSession;
import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.trust.client.XKMS2Client;
import be.fedict.trust.client.exception.ValidationFailedException;
import java.util.List;
/*import com.mycompany.CertificateStatus;
import com.mycompany.OcspClient;*/

/**
 * @author jubarran
 */
@LocalBean
@Stateless
public class AuthenticationServiceOCSPBean implements AuthenticationService {

    private HttpSession session;

    @Override
    public void validateCertificateChain(List<X509Certificate> certificateChain)
            throws SecurityException {


        for(X509Certificate c  : certificateChain ) {
            System.out.println(c.getSubjectDN().toString());
        }

        try {
            String xkmsUrl = new String("http://alpha.rolosa.com:7386/eid-trust-service-ws/xkms2");
            XKMS2Client xkms2Client = new XKMS2Client(xkmsUrl );
            xkms2Client.setLogging(true);
            xkms2Client.validate(certificateChain);
            System.out.println("OK");
            session.setAttribute("AuthenticationResult", "Certificado Validado");
        } catch (ValidationFailedException e) {
            e.printStackTrace();
            session.setAttribute("AuthenticationResult", "Error en la validacion");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void setHttpSessionObject(Object sessionObject) {
        session = (HttpSession) sessionObject;
    }
}
