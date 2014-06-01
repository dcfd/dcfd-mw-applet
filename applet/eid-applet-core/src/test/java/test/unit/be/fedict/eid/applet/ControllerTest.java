/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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

package test.unit.be.fedict.eid.applet;

import be.fedict.eid.applet.DiagnosticTests;
import be.fedict.eid.applet.Messages.MESSAGE_ID;
import be.fedict.eid.applet.Status;
import java.awt.Component;
import java.util.logging.Level;
import java.util.logging.Logger;
import be.fedict.eid.applet.Applet;
import be.fedict.eid.applet.View;
import be.fedict.eid.applet.Messages;
import static org.junit.Assert.assertArrayEquals;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import be.fedict.eid.applet.Controller;
import java.util.Locale;

public class ControllerTest {

	@Test
	public void toHex() throws Exception {
		// setup
		byte[] data = "hello world".getBytes();

		// operate
		String hexData = Controller.toHex(data);

		// verify
		byte[] result = Hex.decode(hexData);
		assertArrayEquals(data, result);
	}

        class AppletView implements View{

            public Applet applet;

                    public void addDetailMessage(String detailMessage) {
                        System.out.println(detailMessage);

                    }

            public void setStatusMessage(Status status, MESSAGE_ID messageId) {
                
            }

            public boolean privacyQuestion(boolean includeAddress, boolean includePhoto, String identityDataUsage) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            public Component getParentComponent() {
                return applet;
            }

            public void addTestResult(DiagnosticTests diagnosticTest, boolean success, String description) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            public void setProgressIndeterminate() {
                System.out.println("setProgressIndeterminate");
            }

            public void resetProgress(int max) {
                System.out.println("Progress: "+max);
            }

            public void increaseProgress() {
                throw new UnsupportedOperationException("Not supported yet.");
            }
        }
        //@Test
        public void TestAut() {

            Messages messages = new Messages(Locale.ENGLISH);
            Controller controller = new Controller(new AppletView(), null, messages);
            try {
                controller.TestIdentityOperation();
            } catch (Exception ex) {
                Logger.getLogger(ControllerTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        //@Test
        public void TestSignOperationGetCertificateChain() {

            Messages messages = new Messages(Locale.ENGLISH);
            Controller controller = new Controller(new AppletView(), null, messages);
            try {
                controller.TestSignOperation();
            } catch (Exception ex) {
                Logger.getLogger(ControllerTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
}
