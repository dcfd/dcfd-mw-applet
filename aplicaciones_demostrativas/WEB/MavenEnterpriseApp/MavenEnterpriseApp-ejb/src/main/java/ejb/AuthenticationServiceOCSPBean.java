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

    @Override
   public void validateCertificateChain(List<X509Certificate> certificateChain)
			throws SecurityException {
       		//LOG.debug("validate certificate chain: " + certificateChain);

		HttpServletRequest httpServletRequest;
		try {
			//TODO:   Perform real OCSP autenticathion.
		} catch (Exception e) {
                    e.printStackTrace();
                }

   }

}
