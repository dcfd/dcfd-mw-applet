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

package be.fedict.eid.idp.sp.protocol.openid;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.MessageExtensionFactory;
import org.openid4java.message.Parameter;
import org.openid4java.message.ParameterList;

import com.google.inject.internal.AbstractIterator;

/**
 * OpenID User Interface Extension v1.0
 * <p/>
 * 
 * @author Wim Vandenhaute
 * @see <a
 *      href="http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html">
 *      OpenID User Interface Extension v1.0</a>
 */
public class UserInterfaceMessage implements MessageExtension,
		MessageExtensionFactory, Iterable<String> {

	public static final String OPENID_NS_UI = "http://specs.openid.net/extensions/ui/1.0";

	public static final String LANGUAGE_PREFIX = "lang";

	private ParameterList parameters;

	public UserInterfaceMessage() {

		parameters = new ParameterList();
	}

	public UserInterfaceMessage(ParameterList parameterList) {

		parameters = parameterList;
	}

	/**
	 * Set the comma seperated list of preferred languages
	 * 
	 * @param languageString
	 *            Comma seperated list of preferred languages
	 */
	public void setLanguages(String languageString) {

		parameters.set(new Parameter(LANGUAGE_PREFIX, languageString));
	}

	/**
	 * Set the list of preferred languages
	 * 
	 * @param languages
	 *            list of preferred languages
	 */
	public void setLanguages(List<String> languages) {

		if (null == languages) {
			return;
		}

		String languageString = "";
		for (String language : languages) {
			languageString += language + ",";
		}
		if (languages.size() > 1) {
			// strip last ','
			languageString = languageString.substring(languageString
					.lastIndexOf(','));
		}

		setLanguages(languageString);
	}

	/**
	 * @return list of preferred languages. Empty list returned if none.
	 */
	public List<String> getLanguages() {

		String languageString = this.parameters
				.getParameterValue(UserInterfaceMessage.LANGUAGE_PREFIX);

		if (null == languageString) {
			return new LinkedList<String>();
		}

		String[] languages = languageString.split(",");
		return Arrays.asList(languages);
	}

	/**
	 * {@inheritDoc}
	 */
	public String getTypeUri() {

		return OPENID_NS_UI;
	}

	/**
	 * {@inheritDoc}
	 */
	public ParameterList getParameters() {

		return parameters;
	}

	/**
	 * {@inheritDoc}
	 */
	public void setParameters(ParameterList params) {

		parameters = params;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean providesIdentifier() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean signRequired() {

		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	public MessageExtension getExtension(ParameterList parameterList,
			boolean isRequest) throws MessageException {

		return new UserInterfaceMessage(parameterList);
	}

	/**
	 * {@inheritDoc}
	 */
	public Iterator<String> iterator() {

		return new AbstractIterator<String>() {

			@SuppressWarnings({ "unchecked" })
			private Iterator<Parameter> source = parameters.getParameters()
					.iterator();

			@Override
			protected String computeNext() {

				while (source.hasNext()) {
					Parameter param = source.next();
					String paramName = param.getKey();
					String paramValue = param.getValue();

					if (paramName.startsWith(LANGUAGE_PREFIX)) {
						return paramValue;
					}
				}

				return endOfData();
			}
		};
	}

}
