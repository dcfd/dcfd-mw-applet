/*
 * eID Identity Provider Project.
 * Copyright (C) 2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */

package be.fedict.eid.idp.sp;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.sp.openid.OpenIDAuthenticationRequestServiceBean;
import be.fedict.eid.idp.sp.saml2.AuthenticationRequestServiceBean;
import be.fedict.eid.idp.sp.saml2.AuthenticationResponseServiceBean;
import be.fedict.eid.idp.sp.wsfed.WSFedAuthenticationRequestServiceBean;
import be.fedict.eid.idp.sp.wsfed.WSFedAuthenticationResponseServiceBean;

public class StartupServletContextListener implements ServletContextListener {

	private static final Log LOG = LogFactory
			.getLog(StartupServletContextListener.class);

	private static final String SAML2_REQUEST_BEAN_JNDI = "be/fedict/eid/idp/sp/saml2/AuthenticationRequestServiceBean";

	private static final String SAML2_RESPONSE_BEAN_JNDI = "be/fedict/eid/idp/sp/saml2/AuthenticationResponseServiceBean";

	private static final String OPENID_REQUEST_BEAN_JNDI = "be/fedict/eid/idp/sp/openid/AuthenticationRequestServiceBean";

	private static final String WS_FED_REQUEST_BEAN_JNDI = "be/fedict/eid/idp/sp/wsfed/AuthenticationRequestServiceBean";

	private static final String WS_FED_RESPONSE_BEAN_JNDI = "be/fedict/eid/idp/sp/wsfed/AuthenticationResponseServiceBean";

	@Override
	public void contextInitialized(ServletContextEvent sce) {

		try {
			bindComponent(SAML2_REQUEST_BEAN_JNDI,
					new AuthenticationRequestServiceBean());
			bindComponent(SAML2_RESPONSE_BEAN_JNDI,
					new AuthenticationResponseServiceBean());
			bindComponent(OPENID_REQUEST_BEAN_JNDI,
					new OpenIDAuthenticationRequestServiceBean());
			bindComponent(WS_FED_REQUEST_BEAN_JNDI,
					new WSFedAuthenticationRequestServiceBean());
			bindComponent(WS_FED_RESPONSE_BEAN_JNDI,
					new WSFedAuthenticationResponseServiceBean());
		} catch (NamingException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
	}

	public static void bindComponent(String jndiName, Object component)
			throws NamingException {

		LOG.debug("bind component: " + jndiName);
		InitialContext initialContext = new InitialContext();
		String[] names = jndiName.split("/");
		Context context = initialContext;
		for (int idx = 0; idx < names.length - 1; idx++) {
			String name = names[idx];
			LOG.debug("name: " + name);
			NamingEnumeration<NameClassPair> listContent = context.list("");
			boolean subContextPresent = false;
			while (listContent.hasMore()) {
				NameClassPair nameClassPair = listContent.next();
				if (!name.equals(nameClassPair.getName())) {
					continue;
				}
				subContextPresent = true;
			}
			if (!subContextPresent) {
				context = context.createSubcontext(name);
			} else {
				context = (Context) context.lookup(name);
			}
		}
		String name = names[names.length - 1];
		context.rebind(name, component);
	}

	public static AuthenticationRequestServiceBean getSaml2RequestBean() {

		return (AuthenticationRequestServiceBean) getComponent(SAML2_REQUEST_BEAN_JNDI);
	}

	public static AuthenticationResponseServiceBean getSaml2ResponseBean() {

		return (AuthenticationResponseServiceBean) getComponent(SAML2_RESPONSE_BEAN_JNDI);
	}

	public static OpenIDAuthenticationRequestServiceBean getOpenIDRequestBean() {

		return (OpenIDAuthenticationRequestServiceBean) getComponent(OPENID_REQUEST_BEAN_JNDI);
	}

	public static WSFedAuthenticationRequestServiceBean getWSFedRequestBean() {

		return (WSFedAuthenticationRequestServiceBean) getComponent(WS_FED_REQUEST_BEAN_JNDI);
	}

	public static WSFedAuthenticationResponseServiceBean getWSFedResponseBean() {

		return (WSFedAuthenticationResponseServiceBean) getComponent(WS_FED_RESPONSE_BEAN_JNDI);
	}

	private static Object getComponent(String jndiName) {

		try {
			InitialContext initialContext = new InitialContext();
			return initialContext.lookup(jndiName);
		} catch (NamingException e) {
			throw new RuntimeException(e);
		}
	}

}
