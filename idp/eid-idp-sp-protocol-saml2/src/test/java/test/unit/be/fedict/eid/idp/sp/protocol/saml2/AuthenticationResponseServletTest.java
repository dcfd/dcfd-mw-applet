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

package test.unit.be.fedict.eid.idp.sp.protocol.saml2;

import static org.junit.Assert.assertEquals;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.ServletTester;

import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationRequestServlet;
import be.fedict.eid.idp.sp.protocol.saml2.post.AuthenticationResponseServlet;

public class AuthenticationResponseServletTest {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationResponseServletTest.class);

	private ServletTester servletTester;

	private String responseLocation;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();

		ServletHolder requestServletHolder = this.servletTester.addServlet(
				AuthenticationRequestServlet.class, "/request");
		requestServletHolder
				.setInitParameter("IdPDestination", "http://idp.be");
		requestServletHolder.setInitParameter("SPDestination", "http://sp.be");

		// response servlet
		ServletHolder responseServletHolder = this.servletTester.addServlet(
				AuthenticationResponseServlet.class, "/response");

		// required init params
		responseServletHolder
				.setInitParameter(
						AuthenticationResponseServlet.RESPONSE_SESSION_ATTRIBUTE_INIT_PARAM,
						"response");
		responseServletHolder.setInitParameter(
				AuthenticationResponseServlet.REDIRECT_PAGE_INIT_PARAM,
				"/target-page");
		responseServletHolder.setInitParameter(
				AuthenticationResponseServlet.ERROR_PAGE_INIT_PARAM,
				"/error-page");
		responseServletHolder
				.setInitParameter(
						AuthenticationResponseServlet.ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM,
						"ErrorMessage");

		this.servletTester.start();
		String context = this.servletTester.createSocketConnector(true);

		this.responseLocation = context + "/response";
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void testDoGet() throws Exception {
		// setup
		LOG.debug("URL: " + this.responseLocation);
		HttpClient httpClient = new HttpClient();
		GetMethod getMethod = new GetMethod(this.responseLocation);

		// operate
		int result = httpClient.executeMethod(getMethod);

		// verify
		LOG.debug("result: " + result);

		assertEquals(HttpServletResponse.SC_NOT_FOUND, result);
	}
}
