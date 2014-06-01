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

package be.fedict.eid.idp.spi;

import be.fedict.eid.applet.service.Identity;

public abstract class IdpUtil {

	public static String getGenderValue(Identity identity) {

		String genderValue;
		switch (identity.getGender()) {
		case MALE:
			genderValue = "1";
			break;
		case FEMALE:
			genderValue = "2";
			break;
		default:
			genderValue = "0";
			break;
		}
		return genderValue;
	}
}
