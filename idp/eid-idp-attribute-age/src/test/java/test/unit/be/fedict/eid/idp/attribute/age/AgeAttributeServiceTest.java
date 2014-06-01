/*
 * eID Identity Provider Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package test.unit.be.fedict.eid.idp.attribute.age;

import static org.junit.Assert.assertNotNull;

import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.idp.attribute.age.AgeAttributeService;
import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.common.AttributeType;
import be.fedict.eid.idp.spi.DefaultAttribute;

public class AgeAttributeServiceTest {

	private static final Log LOG = LogFactory.getLog(AgeAttributeServiceTest.class);
	
	@Test
	public void testAge() throws Exception {
		// setup
		AgeAttributeService testedInstance = new AgeAttributeService();
		Map<String, Attribute> attributeMap = new HashMap<String, Attribute>();
		GregorianCalendar gregorianCalendar = new GregorianCalendar();
		gregorianCalendar.set(1979, 0, 15);
		attributeMap.put(DefaultAttribute.DATE_OF_BIRTH.getUri(), new Attribute(
				DefaultAttribute.DATE_OF_BIRTH.getUri(), AttributeType.DATE, gregorianCalendar));
		
		// operate
		testedInstance.addAttribute(attributeMap);
		
		// verify
		Attribute ageAttribute = attributeMap.get("be:fedict:eid:idp:age");
		assertNotNull(ageAttribute);
		LOG.debug("age: " + ageAttribute.getValue());
	}
}
