/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package ejb;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.LocalBean;
import javax.ejb.Stateless;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/*import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;*/
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.AuthenticationService;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import com.mycompany.CertificateStatus;
import com.mycompany.OcspClient;

/**
 *
 * @author jubarran
 * //@LocalBinding(jndiBinding = "java:global/eid/applet/AuthenticationServiceOCSPBean")
 */
@LocalBean
@Stateless //(mappedName="theAuthenticationServiceOCSPBean")
public class AuthenticationServiceOCSPBean  implements AuthenticationService {

   /* private static final Log LOG = LogFactory
			.getLog(AuthenticationServiceOCSPBean.class);*/

    private HttpSession session;
    @Override
   public void validateCertificateChain(List<X509Certificate> certificateChain)
			throws SecurityException {
       		//LOG.debug("validate certificate chain: " + certificateChain);

		
		try {
                        OcspClient oscpClient = new OcspClient(certificateChain.get(0));
                        oscpClient.getPublicKeyCertificate().checkValidity();
                        CertificateStatus status = oscpClient.consultarEstadoDeCertificado(oscpClient.getPublicKeyCertificate(), certificateChain.get(1));
                        if (status == CertificateStatus.Good) {
                            System.out.println("OK");
                            session.setAttribute("AuthenticationResult", "Certificado Validado");
                        } else if (status == CertificateStatus.Revoked) {
                            System.out.println("Revocado");
                            //out_Error.append("Certificado Revocado");
                            session.setAttribute("AuthenticationResult", "Certificado Recovado");
                        } else {
                            System.out.println("Desconocido");
                            //out_Error.append("Certificado/Respuesta Desconocido(s)");
                            session.setAttribute("AuthenticationResult", "Certificado Desconocido");
                        }
		} catch (Exception e) {
                    e.printStackTrace();
                }

   }
    public void setHttpSessionObject(Object sessionObject) {
        session = (HttpSession)sessionObject;
    }

}
