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

package be.fedict.eid.idp.common.saml2;

/**
 * Exception thrown if validation of a SAML v2.0 Assertion fails.
 * 
 * @author Wim Vandenhaute
 */
public class AssertionValidationException extends Exception {

	private static final long serialVersionUID = 1L;

	public AssertionValidationException(String message, Throwable cause) {
		super(message, cause);
	}

	public AssertionValidationException(Throwable cause) {
		super(cause);
	}

	public AssertionValidationException(String message) {
		super(message);
	}
}
