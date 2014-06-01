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
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xpath.XPathAPI;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.ServletTester;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.tidy.Tidy;

import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationRequestServlet;

public class AuthenticationRequestServletTest {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestServletTest.class);

	private ServletTester servletTester;

	private String location;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		ServletHolder servletHolder = this.servletTester.addServlet(
				AuthenticationRequestServlet.class, "/");
		servletHolder.setInitParameter("IdPDestination", "http://idp.be");
		servletHolder.setInitParameter("SPDestination", "http://sp.be");
		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true);
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void testDoGet() throws Exception {
		// setup
		LOG.debug("URL: " + this.location);
		HttpClient httpClient = new HttpClient();
		GetMethod getMethod = new GetMethod(this.location);

		// operate
		int result = httpClient.executeMethod(getMethod);

		// verify
		assertEquals(HttpServletResponse.SC_OK, result);
		String responseBody = getMethod.getResponseBodyAsString();
		LOG.debug("Response body: " + responseBody);
		Tidy tidy = new Tidy();
		Document document = tidy.parseDOM(
				new ByteArrayInputStream(getMethod.getResponseBody()), null);

		//Node actionNode = XPathAPI.selectSingleNode(document,
		//		"//form[@action='http://idp.be']");
		//assertNotNull(actionNode);
	}
}
