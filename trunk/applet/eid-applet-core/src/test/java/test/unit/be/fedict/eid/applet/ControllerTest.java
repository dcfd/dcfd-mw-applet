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
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ControllerTest {

	@Test
    public void toHex() throws Exception {
        /*CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List mylist = new ArrayList();
        String path = "/usr/lib/dcfd/certificados";
        File folder = new File(path);
        File[] files = folder.listFiles();
        for (File file : files) {
            if (file.isFile()) {
                FileInputStream in = new FileInputStream(file);
                X509Certificate c = (X509Certificate) cf.generateCertificate(in);
                mylist.add(c);
            }
        }

        Map<String, X509Certificate> mapOfCertificates = new HashMap<String, X509Certificate>();

        for (Object object : mylist) {
            X509Certificate c = (X509Certificate) object;
            BigInteger serialNumber = c.getSerialNumber();
            System.out.println(c.getSubjectDN() + "|" + serialNumber.toString());
            System.out.println("Issued by " + c.getIssuerDN());
            System.out.println("SubjectKeyIdentifier " + Arrays.toString(c.getExtensionValue("2.5.29.14")));
            System.out.println("AuthorityKeyIdentifier " + Arrays.toString(c.getExtensionValue("2.5.29.35")) + "\n");
            mapOfCertificates.put(GetKey(c.getExtensionValue("2.5.29.14"), false), c);
        }

        
        Set<String> keys = mapOfCertificates.keySet();
        for (String key : keys) {
            System.out.println(key);
            List certChain = new ArrayList();
            X509Certificate c = mapOfCertificates.get(key);
            byte[] extension = c.getExtensionValue("2.5.29.35");
            while (extension != null) {
                String authorityKey = GetKey(extension, true);
                X509Certificate authCertificate = mapOfCertificates.get(authorityKey);
                certChain.add(authCertificate);
                extension = authCertificate.getExtensionValue("2.5.29.35");
            }
            for (Object object : certChain) {
                X509Certificate certificate = (X509Certificate) object;
                BigInteger serialNumber = certificate.getSerialNumber();
                System.out.println(certificate.getSubjectDN() + "|" + serialNumber.toString());
                System.out.println("Issued by " + certificate.getIssuerDN());
            }
        }*/

        // setup
        byte[] data = "hello world".getBytes();

        // operate
        String hexData = Controller.toHex(data);

        // verify
        byte[] result = Hex.decode(hexData);
        assertArrayEquals(data, result);
    }

    private String GetKey(byte[] in_Value, boolean in_IsAuthority) {
        /*
         * Only complying with method (1) of RFC5280: (160bits  = 20 bytes)
         * For CA certificates, subject key identifiers SHOULD be derived from
the public key or a method that generates unique values.  Two common
methods for generating key identifiers from the public key are:

  (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
       value of the BIT STRING subjectPublicKey (excluding the tag,
       length, and number of unused bits).
  (2) The keyIdentifier is composed of a four-bit type field with
       the value 0100 followed by the least significant 60 bits of
       the SHA-1 hash of the value of the BIT STRING
       subjectPublicKey (excluding the tag, length, and number of
       unused bits).

         */
        String key = "";
        if (in_Value.length > 6) {
            int offset = in_IsAuthority ? 5 : 3;
            key = Arrays.toString(Arrays.copyOfRange(in_Value, offset, in_Value.length));
        }
        return key;
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

        //@Test
        public void TestAuthnOperation() {

            Messages messages = new Messages(Locale.ENGLISH);
            Controller controller = new Controller(new AppletView(), null, messages);
            try {
                controller.TestAuthnOperation();
            } catch (Exception ex) {
                Logger.getLogger(ControllerTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
}
