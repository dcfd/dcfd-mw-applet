/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

import static org.junit.Assert.assertEquals;

import java.net.HttpURLConnection;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.openid4java.association.Association;
import org.openid4java.association.AssociationSessionType;
import org.openid4java.association.DiffieHellmanSession;
import org.openid4java.message.AssociationRequest;
import org.openid4java.message.AssociationResponse;
import org.openid4java.message.ParameterList;

public class OpenIDAssociationsTest {

	private static final Log LOG = LogFactory
			.getLog(OpenIDAssociationsTest.class);

	@Test
	public void testEstablishAssociation() throws Exception {
		// setup
		AssociationSessionType associationSessionType = AssociationSessionType.NO_ENCRYPTION_SHA1MAC;
		String opEndpoint = "https://www.e-contract.be/eid-idp/protocol/openid/auth";

		// operate
		DiffieHellmanSession dhSession;
		if (null != associationSessionType.getHAlgorithm()) {
			// Diffie-Hellman
			DHParameterSpec dhParameterSpec = DiffieHellmanSession
					.getDefaultParameter();
			dhSession = DiffieHellmanSession.create(associationSessionType,
					dhParameterSpec);

		} else {
			dhSession = null;
		}
		AssociationRequest associationRequest = AssociationRequest
				.createAssociationRequest(associationSessionType, dhSession);
		LOG.debug("association type: "
				+ associationRequest.getType().getAssociationType());
		LOG.debug("session type: "
				+ associationRequest.getType().getSessionType());

		Map<String, String> parameters = associationRequest.getParameterMap();

		HttpClient httpClient = new HttpClient();
		httpClient.getHostConfiguration().setProxy("proxy.yourict.net", 8080);
		PostMethod postMethod = new PostMethod(opEndpoint);
		for (Map.Entry<String, String> parameter : parameters.entrySet()) {
			postMethod.addParameter(parameter.getKey(), parameter.getValue());
		}

		int statusCode = httpClient.executeMethod(postMethod);
		LOG.debug("status code: " + statusCode);
		assertEquals(HttpURLConnection.HTTP_OK, statusCode);

		postMethod.getResponseBody();

		ParameterList responseParameterList = ParameterList
				.createFromKeyValueForm(postMethod.getResponseBodyAsString());
		AssociationResponse associationResponse = AssociationResponse
				.createAssociationResponse(responseParameterList);

		Association association = associationResponse.getAssociation(dhSession);
		LOG.debug("association type: " + association.getType());
		LOG.debug("association handle: " + association.getHandle());
		LOG.debug("association expiry: " + association.getExpiry());
		SecretKey secretKey = association.getMacKey();
		LOG.debug("association MAC key algo: " + secretKey.getAlgorithm());
	}
	
	/**
	 * http://code.google.com/p/openid4java/issues/detail?id=192
	 * 
	 * @throws Exception
	 */
	@Test
	public void testEstablishAssociationSteam() throws Exception {
		// setup
		AssociationSessionType associationSessionType = AssociationSessionType.NO_ENCRYPTION_SHA1MAC;
		String opEndpoint = "https://steamcommunity.com/openid/login";

		// operate
		DiffieHellmanSession dhSession;
		if (null != associationSessionType.getHAlgorithm()) {
			// Diffie-Hellman
			DHParameterSpec dhParameterSpec = DiffieHellmanSession
					.getDefaultParameter();
			dhSession = DiffieHellmanSession.create(associationSessionType,
					dhParameterSpec);

		} else {
			dhSession = null;
		}
		AssociationRequest associationRequest = AssociationRequest
				.createAssociationRequest(associationSessionType, dhSession);
		LOG.debug("association type: "
				+ associationRequest.getType().getAssociationType());
		LOG.debug("session type: "
				+ associationRequest.getType().getSessionType());

		Map<String, String> parameters = associationRequest.getParameterMap();

		HttpClient httpClient = new HttpClient();
		httpClient.getHostConfiguration().setProxy("proxy.yourict.net", 8080);
		PostMethod postMethod = new PostMethod(opEndpoint);
		for (Map.Entry<String, String> parameter : parameters.entrySet()) {
			postMethod.addParameter(parameter.getKey(), parameter.getValue());
		}

		int statusCode = httpClient.executeMethod(postMethod);
		LOG.debug("status code: " + statusCode);
		assertEquals(HttpURLConnection.HTTP_OK, statusCode);

		postMethod.getResponseBody();

		ParameterList responseParameterList = ParameterList
				.createFromKeyValueForm(postMethod.getResponseBodyAsString());
		AssociationResponse associationResponse = AssociationResponse
				.createAssociationResponse(responseParameterList);

		Association association = associationResponse.getAssociation(dhSession);
		LOG.debug("association type: " + association.getType());
		LOG.debug("association handle: " + association.getHandle());
		LOG.debug("association expiry: " + association.getExpiry());
		SecretKey secretKey = association.getMacKey();
		LOG.debug("association MAC key algo: " + secretKey.getAlgorithm());
	}
}
