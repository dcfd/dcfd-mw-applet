/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-2012 FedICT.
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

package be.fedict.eid.idp.model.bean;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;

import be.fedict.eid.idp.model.Statistics;

@Singleton
@ConcurrencyManagement(ConcurrencyManagementType.CONTAINER)
public class StatisticsBean implements Statistics {

	private Map<String, Long> authenticationsPerProtocol;

	private long totalAuthenticationCount;

	@PostConstruct
	public void postConstruct() {
		this.authenticationsPerProtocol = new HashMap<String, Long>();
		this.totalAuthenticationCount = 0;
	}

	@Override
	@Lock(LockType.WRITE)
	public void countAuthentication(String protocolIdentifier) {
		this.totalAuthenticationCount++;
		Long authenticationCount = this.authenticationsPerProtocol
				.get(protocolIdentifier);
		if (null == authenticationCount) {
			this.authenticationsPerProtocol.put(protocolIdentifier,
					Long.valueOf(1));
		} else {
			this.authenticationsPerProtocol.put(protocolIdentifier,
					authenticationCount + 1);
		}
	}

	@Override
	@Lock(LockType.WRITE)
	public Map<String, Long> getProtocolStatistics() {
		Map<String, Long> copy = new HashMap<String, Long>();
		copy.putAll(this.authenticationsPerProtocol);
		return copy;
	}

	@Override
	@Lock(LockType.READ)
	public long getTotalAuthenticationCount() {
		return this.totalAuthenticationCount;
	}
}
