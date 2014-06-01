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

package be.fedict.eid.idp.mbean;

import java.util.Map;

import javax.ejb.EJB;
import javax.management.openmbean.CompositeDataSupport;
import javax.management.openmbean.CompositeType;
import javax.management.openmbean.OpenDataException;
import javax.management.openmbean.OpenType;
import javax.management.openmbean.SimpleType;

import org.jboss.ejb3.annotation.Management;
import org.jboss.ejb3.annotation.Service;

import be.fedict.eid.idp.model.Statistics;

@Service(objectName = "idp:service=Statistics")
@Management(StatisticsServiceMBean.class)
public class StatisticsService implements StatisticsServiceMBean {

	@EJB
	private Statistics statistics;

	@Override
	public CompositeDataSupport getProtocolStatistics() {
		Map<String, Long> protocolStatistics = this.statistics
				.getProtocolStatistics();
		try {
			String[] itemNames = protocolStatistics.keySet().toArray(
					new String[] {});
			OpenType<?>[] itemTypes = new OpenType<?>[itemNames.length];
			Object[] itemValues = new Object[itemNames.length];
			for (int idx = 0; idx < itemTypes.length; idx++) {
				itemTypes[idx] = SimpleType.LONG;
				itemValues[idx] = protocolStatistics.get(itemNames[idx]);
			}
			CompositeType compositeType = new CompositeType(
					"ProtocolStatistic", "A row with protocol statistics.",
					itemNames, itemNames, itemTypes);

			CompositeDataSupport compositeData = new CompositeDataSupport(
					compositeType, itemNames, itemValues);
			return compositeData;
		} catch (OpenDataException e) {
			return null;
		}
	}

	@Override
	public long getTotalAuthenticationCount() {
		return this.statistics.getTotalAuthenticationCount();
	}
}
