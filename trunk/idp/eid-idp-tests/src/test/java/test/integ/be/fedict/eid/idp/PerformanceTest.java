/*
 * eID Identity Provider Project.
 * Copyright (C) 2013 FedICT.
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

package test.integ.be.fedict.eid.idp;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

public class PerformanceTest {

	private static final Log LOG = LogFactory.getLog(PerformanceTest.class);

	@Test
	public void testAJPProxyPerformance() throws Exception {

		int count = 0;
		while (true) {
			count++;
			LOG.debug("count: " + count);
			HttpClient httpClient = new HttpClient();
			GetMethod getMethod = new GetMethod(
					"http://localhost/eid-idp/authentication");
			httpClient.executeMethod(getMethod);
		}
	}
}
