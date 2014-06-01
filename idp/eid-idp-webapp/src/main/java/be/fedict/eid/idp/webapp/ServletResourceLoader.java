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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

import javax.servlet.ServletContext;

import com.sun.xml.ws.transport.http.ResourceLoader;

final class ServletResourceLoader implements ResourceLoader {
	private final ServletContext context;

	public ServletResourceLoader(ServletContext context) {
		this.context = context;
	}

	public URL getResource(String path) throws MalformedURLException {
		return context.getResource(path);
	}

	public URL getCatalogFile() throws MalformedURLException {
		return getResource("/WEB-INF/jax-ws-catalog.xml");
	}

	public Set<String> getResourcePaths(String path) {
		return context.getResourcePaths(path);
	}
}
