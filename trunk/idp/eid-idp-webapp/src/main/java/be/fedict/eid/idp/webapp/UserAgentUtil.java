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

package be.fedict.eid.idp.webapp;

/**
 * Utility class for user agent detection.
 */
public abstract class UserAgentUtil {

	// Apple
	private static final String IPHONE = "iphone";
	private static final String IPOD = "ipod";
	private static final String IPAD = "ipad";

	// Android
	private static final String ANDROID = "android";

	// Symbian
	private static final String SYMBIAN = "symbian";
	private static final String S60 = "series60";
	private static final String S70 = "series70";
	private static final String S80 = "series80";
	private static final String S90 = "series90";

	// Windows Mobile
	private static final String WINDOWS_PHONE_7 = "windows phone os 7";
	private static final String WINDOWS_MOBILE = "windows ce";
	private static final String WINDOWS_IE_MOBILE = "iemobile";

	// Blackberry
	private static final String BLACKBERRY = "blackberry";

	public static boolean isSmartPhone(String userAgent) {

		if (null == userAgent) {
			return false;
		}

		String lowerUserAgent = userAgent.toLowerCase();

		return isIphoneIpodIpad(lowerUserAgent) || isAndroid(lowerUserAgent)
				|| isWindowsMobile(lowerUserAgent) || isSymbian(lowerUserAgent)
				|| isBlackberry(lowerUserAgent);
	}

	private static boolean isIphoneIpodIpad(String userAgent) {
		return isIphone(userAgent) || isIpod(userAgent) || isIpad(userAgent);
	}

	private static boolean isIphone(String userAgent) {
		return userAgent.indexOf(IPHONE) != -1;
	}

	private static boolean isIpod(String userAgent) {
		return userAgent.indexOf(IPOD) != -1;
	}

	private static boolean isIpad(String userAgent) {
		return userAgent.indexOf(IPAD) != -1;
	}

	private static boolean isAndroid(String userAgent) {
		return userAgent.indexOf(ANDROID) != -1;
	}

	private static boolean isSymbian(String userAgent) {
		return userAgent.indexOf(SYMBIAN) != -1 || userAgent.indexOf(S60) != -1
				|| userAgent.indexOf(S70) != -1 || userAgent.indexOf(S80) != -1
				|| userAgent.indexOf(S90) != -1;
	}

	private static boolean isWindowsMobile(String userAgent) {
		return userAgent.indexOf(WINDOWS_PHONE_7) != -1
				|| userAgent.indexOf(WINDOWS_MOBILE) != -1
				|| userAgent.indexOf(WINDOWS_IE_MOBILE) != -1;
	}

	private static boolean isBlackberry(String userAgent) {
		return userAgent.indexOf(BLACKBERRY) != -1;
	}
}
