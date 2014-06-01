/*
 * eID Identity Provider Project.
 * Copyright (C) 2012 FedICT.
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

import java.io.IOException;

import javax.ejb.EJB;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;

/**
 * X-XSS-Protection filter.
 * 
 * @author Frank Cornelis
 * 
 */
public class XSSProtectionFilter implements Filter {

	private static final Log LOG = LogFactory.getLog(XSSProtectionFilter.class);

	@EJB
	private Configuration configuration;

	@Override
	public void destroy() {
		LOG.debug("destroy");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		Boolean xssProtection = this.configuration.getValue(
				ConfigProperty.XSS_PROTECTION, Boolean.class);
		if (null != xssProtection) {
			if (xssProtection.equals(Boolean.TRUE)) {
				HttpServletResponse httpServletResponse = (HttpServletResponse) response;
				httpServletResponse.setHeader("X-XSS-Protection",
						"1; mode=block");
			}
		}
		chain.doFilter(request, response);
	}

	@Override
	public void init(FilterConfig config) throws ServletException {
		LOG.debug("init");
	}
}
