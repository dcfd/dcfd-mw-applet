package be.fedict.eid.applet.sc;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SLOT_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import be.fedict.eid.applet.DiagnosticTests;
import be.fedict.eid.applet.Dialogs;
import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.View;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.util.AbstractList;
import java.util.ArrayList;
import sun.security.x509.X509CertImpl;

public class Pkcs11Eid {

	private final View view;

	private PKCS11 pkcs11;

	private long slotIdx;

	private String slotDescription;

	private Messages messages;
        
        private String authenticationLabel;
        
        private String signatureLabel;
        
	private List<X509Certificate> authnCertificateChain;

        private List<X509Certificate> signCertificateChain;

        private Map<String, X509Certificate> mapOfCertificates;

	public Pkcs11Eid(View view, Messages messages) {
		this.view = view;
		this.messages = messages;

                mapOfCertificates = new HashMap<String, X509Certificate>();
                authnCertificateChain = new ArrayList<X509Certificate>();
                signCertificateChain = new ArrayList<X509Certificate>();


                String path = "";

                FileInputStream stream = null;

                String osName = System.getProperty("os.name");

		if (osName.startsWith("Linux") || osName.startsWith("Mac")) {
                    path = "/usr/lib/dcfd/certificados";

                } else { //Windows
                    path = "C:\\Firma Digital\\certificados\\";
                }

                
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    List mylist = new ArrayList();
                    
                    File folder = new File(path);
                    File[] files = folder.listFiles();
                    for (File file : files) {
                        if (file.isFile()) {
                            stream = new FileInputStream(file);
                            X509Certificate c = (X509Certificate) cf.generateCertificate(stream);
                            mylist.add(c);
                        }
                    }
                    for (Object object : mylist) {
                        X509Certificate c = (X509Certificate) object;
                        mapOfCertificates.put(GetKey(c.getExtensionValue("2.5.29.14"), false), c);
                    }
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                }   catch (IOException ex) {
                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                } catch (java.security.cert.CertificateException ex) {
                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                }
                finally {
                    try {
                        stream.close();
                    } catch (IOException ex) {
                        Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
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

	/**
	 * Gives back the PKCS11 wrapper. This is just for debugging purposes.
	 * 
	 * @return
	 */
	public PKCS11 getPkcs11() {
		return this.pkcs11;
	}

        private void buildCertificatePath(List<X509Certificate> in_out_List, X509Certificate in_Seed) {
            in_out_List.clear();
            in_out_List.add(in_Seed);
            //System.out.println(key);
            byte[] seedExtension = in_Seed.getExtensionValue("2.5.29.35");
            X509Certificate c = mapOfCertificates.get(GetKey(seedExtension, true));
            if(c != null) {
                in_out_List.add(c);
                byte[] extension = c.getExtensionValue("2.5.29.35");
                while (extension != null) {
                    String authorityKey = GetKey(extension, true);
                    X509Certificate authCertificate = mapOfCertificates.get(authorityKey);
                    in_out_List.add(authCertificate);
                    extension = authCertificate.getExtensionValue("2.5.29.35");
                }
            }
            if(in_out_List.size() != 4) {
                throw new RuntimeException("No es posible crear la cadena de confianza. No estan presentes todos los certificados de firma digital en el Equipo del Usuario Final");
            }
        }

        public final int rootCACertificate = 0;
        public final int childCACertificate = 1;
        public final int child_childCACertificate = 2;

        /**
         *
         * @param in_CAType Certiificate Authority type
         * 0 - rootCertificate
         * 1 - childCertificate
         * 2 - child_childCertificate
         * @return
         */

	private X509Certificate getIssuerCert(int in_CAType) {
                String osName = System.getProperty("os.name");
		File certificate = null;
		if (osName.startsWith("Linux") || osName.startsWith("Mac")) {
			/*
			 * Covers 4.0 eID Middleware.
			 */
                    switch(in_CAType){
                        case rootCACertificate:
                            certificate = new File("/usr/lib/dcfd/certificados/CA RAIZ NACIONAL COSTA RICA.cer");
                            break;
                        case childCACertificate:
                            certificate = new File("/usr/lib/dcfd/certificados/CA POLITICA PERSONA FISICA - COSTA RICA.cer");
                            break;
                        case child_childCACertificate:
                            certificate = new File("/usr/lib/dcfd/certificados/CA SINPE - PERSONA FISICA.cer");
                            break;
                        default:
                            Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, "Unknown Certificate Authority Type: "+in_CAType);
                            return null;
                    }
                } else { //Windows
                    switch(in_CAType){
                        case rootCACertificate:
                            certificate = new File("C:\\Firma Digital\\certificados\\CA RAIZ NACIONAL COSTA RICA.cer");
                            break;
                        case childCACertificate:
                            certificate = new File("C:\\Firma Digital\\certificados\\CA POLITICA PERSONA FISICA - COSTA RICA.cer");
                            break;
                        case child_childCACertificate:
                            certificate = new File("C:\\Firma Digital\\certificados\\CA SINPE - PERSONA FISICA.cer");
                            break;
                        default:
                            Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, "Unknown Certificate Authority Type: "+in_CAType);
                            return null;
                    }
                }
                if(certificate != null) {

			if (certificate.exists()) {
                            FileInputStream stream = null;
                            try {
                                stream = new FileInputStream(certificate);
                                int lenght = (int) ( certificate.length());
                                byte[] buf1 = new byte[lenght];
                                stream.read(buf1);
                                return new  X509CertImpl(buf1);
                            } catch (FileNotFoundException ex) {
                                Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                            }   catch (IOException ex) {
                                Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (java.security.cert.CertificateException ex) {
                                Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            finally {
                                try {
                                    stream.close();
                                } catch (IOException ex) {
                                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            }
			}
                }
		return null;
        }

        private String getPkcs11Path() throws PKCS11NotFoundException {
		String osName = System.getProperty("os.name");
		File pkcs11File;
		if (osName.startsWith("Linux")) {
			/*
			 * Covers 4.0 eID Middleware.
			 */
			pkcs11File = new File("/usr/local/lib/libbeidpkcs11.so");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
		} else if (osName.startsWith("Mac")) {
			/*
			 * eID MW 4.0
			 */
			pkcs11File = new File("/usr/local/lib/libbeidpkcs11.dylib");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
		} else {
			/*
			 * eID Middleware 4.0 - XP
			 */
			pkcs11File = new File("C:\\Firma Digital\\mw\\beidpkcs11.dll");
                        
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}

                        pkcs11File = new File("C:\\WINDOWS\\system32\\beidpkcs11.dll");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * Windows 7 when installing the 32-bit eID MW on a 64-bit platform.
			 */
			pkcs11File = new File("C:\\Windows\\SysWOW64\\beidpkcs11.dll");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
		}
		throw new PKCS11NotFoundException();
	}

	private PKCS11 loadPkcs11(String pkcs11Path)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException, SecurityException, NoSuchMethodException {
		try {
			/*
			 * Java 1.6
			 */
			Method getInstanceMethod = PKCS11.class.getMethod("getInstance",
					String.class, String.class, CK_C_INITIALIZE_ARGS.class,
					Boolean.TYPE);
			CK_C_INITIALIZE_ARGS ck_c_initialize_args = new CK_C_INITIALIZE_ARGS();
			PKCS11 pkcs11 = (PKCS11) getInstanceMethod.invoke(null, pkcs11Path,
					"C_GetFunctionList", ck_c_initialize_args, false);
			return pkcs11;
		} catch (NoSuchMethodException e) {
			/*
			 * Java 1.5
			 */
			this.view.addDetailMessage("PKCS11 getInstance Java 1.5 fallback");
			Method getInstanceMethod = PKCS11.class.getMethod("getInstance",
					String.class, CK_C_INITIALIZE_ARGS.class, Boolean.TYPE);
			PKCS11 pkcs11 = (PKCS11) getInstanceMethod.invoke(null, pkcs11Path,
					null, false);
			return pkcs11;
		}
	}

	public List<String> getReaderList() throws PKCS11NotFoundException,
			IllegalArgumentException, SecurityException,
			IllegalAccessException, InvocationTargetException,
			NoSuchMethodException, PKCS11Exception, NoSuchFieldException {
		List<String> readerList = new LinkedList<String>();
		String pkcs11Path = getPkcs11Path();
		this.pkcs11 = loadPkcs11(pkcs11Path);
		long[] slotIdxs = this.pkcs11.C_GetSlotList(false);
		for (long slotIdx : slotIdxs) {
			CK_SLOT_INFO slotInfo = this.pkcs11.C_GetSlotInfo(slotIdx);
			String reader = new String(slotInfo.slotDescription).trim();
			readerList.add(reader);
		}
		cFinalize();
		return readerList;
	}
        
	public boolean hasCardReader() throws IOException, PKCS11Exception,
			InterruptedException, NoSuchFieldException, IllegalAccessException,
			IllegalArgumentException, SecurityException,
			InvocationTargetException, NoSuchMethodException {
		String pkcs11Path = getPkcs11Path();
                this.view.addDetailMessage("PKCS#11 path: " + pkcs11Path);
                this.pkcs11 = loadPkcs11(pkcs11Path);
                CK_INFO ck_info = this.pkcs11.C_GetInfo();
                this.view.addDetailMessage("library description: "
                                + new String(ck_info.libraryDescription).trim());
                this.view.addDetailMessage("manufacturer ID: "
                                + new String(ck_info.manufacturerID).trim());
                this.view.addDetailMessage("library version: "
                                + Integer.toString(ck_info.libraryVersion.major, 16) + "."
                                + Integer.toString(ck_info.libraryVersion.minor, 16));
                this.view.addDetailMessage("cryptoki version: "
                                + Integer.toString(ck_info.cryptokiVersion.major, 16) + "."
                                + Integer.toString(ck_info.cryptokiVersion.minor, 16));
                long[] slotIdxs = this.pkcs11.C_GetSlotList(false);
                if (0 == slotIdxs.length) {
                    this.view.addDetailMessage("no card readers connected?");
                    return false;
                }
                return true;
	}

	public void waitForCardReader() throws IOException, PKCS11Exception,
			InterruptedException, NoSuchFieldException, IllegalAccessException,
			IllegalArgumentException, SecurityException,
			InvocationTargetException, NoSuchMethodException {
		while (true) {
			if (true == hasCardReader()) {
				return;
			}
			Thread.sleep(1000);
		}
	}

	public boolean isEidPresent() throws IOException, PKCS11Exception,
			InterruptedException, NoSuchFieldException, IllegalAccessException,
			IllegalArgumentException, SecurityException,
			InvocationTargetException, NoSuchMethodException {
		String pkcs11Path = getPkcs11Path();
		this.view.addDetailMessage("PKCS#11 path: " + pkcs11Path);
		this.pkcs11 = loadPkcs11(pkcs11Path);
		CK_INFO ck_info = this.pkcs11.C_GetInfo();
		this.view.addDetailMessage("library description: "
				+ new String(ck_info.libraryDescription).trim());
		this.view.addDetailMessage("manufacturer ID: "
				+ new String(ck_info.manufacturerID).trim());
		this.view.addDetailMessage("library version: "
				+ Integer.toString(ck_info.libraryVersion.major, 16) + "."
				+ Integer.toString(ck_info.libraryVersion.minor, 16));
		this.view.addDetailMessage("cryptoki version: "
				+ Integer.toString(ck_info.cryptokiVersion.major, 16) + "."
				+ Integer.toString(ck_info.cryptokiVersion.minor, 16));
		long[] slotIdxs = this.pkcs11.C_GetSlotList(false);
		if (0 == slotIdxs.length) {
			this.view.addDetailMessage("no card readers connected?");
		}
		for (long slotIdx : slotIdxs) {
			CK_SLOT_INFO slotInfo = this.pkcs11.C_GetSlotInfo(slotIdx);
			this.view.addDetailMessage("reader: "
					+ new String(slotInfo.slotDescription).trim());
			if ((slotInfo.flags & PKCS11Constants.CKF_TOKEN_PRESENT) != 0) {
				CK_TOKEN_INFO tokenInfo;
				try {
					tokenInfo = this.pkcs11.C_GetTokenInfo(slotIdx);
				} catch (PKCS11Exception e) {
					/*
					 * Can occur when someone just removed the eID card.
					 * CKR_TOKEN_NOT_PRESENT.
					 */
					continue;
				}
                                String tokenInfoLabel =  new String(tokenInfo.label);
				if (tokenInfoLabel.startsWith("IDProtect")) {
					this.view.addDetailMessage("DCFD card labeled: "+tokenInfoLabel+" is in slot: "
							+ slotIdx);
					this.slotIdx = slotIdx;
					this.slotDescription = new String(slotInfo.slotDescription)
							.trim();
                                        return GetAvailableLabels();
				}
			}
		}
		cFinalize();
		return false;
	}

	public String getSlotDescription() {
		return this.slotDescription;
	}

	private void cFinalize() throws PKCS11Exception, NoSuchFieldException,
			IllegalAccessException {
		this.pkcs11.C_Finalize(null);
		Field moduleMapField = PKCS11.class.getDeclaredField("moduleMap");
		moduleMapField.setAccessible(true);
		Map<?, ?> moduleMap = (Map<?, ?>) moduleMapField.get(null);
		moduleMap.clear(); // force re-execution of C_Initialize next time
		this.pkcs11 = null;
	}

	/**
	 * Wait for eID card presence in some token slot.
	 * 
	 * @throws IOException
	 * @throws PKCS11Exception
	 * @throws InterruptedException
	 * @throws NoSuchFieldException
	 * @throws IllegalAccessException
	 * @throws NoSuchMethodException
	 * @throws InvocationTargetException
	 * @throws SecurityException
	 * @throws IllegalArgumentException
	 */
	public void waitForEidPresent() throws IOException, PKCS11Exception,
			InterruptedException, NoSuchFieldException, IllegalAccessException,
			IllegalArgumentException, SecurityException,
			InvocationTargetException, NoSuchMethodException {
		while (true) {
			if (true == isEidPresent()) {
				return;
			}
			Thread.sleep(1000);
		}
	}

        private boolean GetAvailableLabels() {
            boolean result = false;
             if(this.pkcs11 != null) {
                long session;
                try {

                       session = this.pkcs11.C_OpenSession(this.slotIdx, PKCS11Constants.CKF_SERIAL_SESSION, null, null);

                        CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[2];
                        attributes[0] = new CK_ATTRIBUTE();
                        attributes[0].type = PKCS11Constants.CKA_CLASS;
                        attributes[0].pValue = PKCS11Constants.CKO_CERTIFICATE;
                        attributes[1] = new CK_ATTRIBUTE();
                        attributes[1].type = PKCS11Constants.CKA_CERTIFICATE_TYPE;
                        attributes[1].pValue = PKCS11Constants.CKC_X_509;
                        this.pkcs11.C_FindObjectsInit(session, attributes);


                        try {
                                long[] certHandles = this.pkcs11.C_FindObjects(session, 4);
                                if (0 == certHandles.length) {
                                        /*
                                         * In case of OpenSC PKCS#11.
                                         */
                                        throw new RuntimeException("cannot find objects via PKCS#11");
                                }
                                if(certHandles.length == 2 ) {

                                    char[] certLabel = null;
                                    CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
                                    template[0] = new CK_ATTRIBUTE();
                                    template[0].type = PKCS11Constants.CKA_LABEL;
                                    this.pkcs11.C_GetAttributeValue(session, certHandles[0], template);
                                    if(template[0].pValue != null) {
                                            certLabel = (char[]) template[0].pValue;
                                            this.setAuthenticationLabel(new String(certLabel));
                                    }
                                    else { result =  false;}
                                    this.pkcs11.C_GetAttributeValue(session, certHandles[1], template);
                                    if(template[0].pValue != null) {
                                            certLabel = (char[]) template[0].pValue;
                                            this.setSignatureLabel(new String(certLabel));
                                    }
                                    else { result =  false;}
                                }
                        }
                        finally {
                                this.pkcs11.C_FindObjectsFinal(session);
                        }
                        result = true;

                } catch (PKCS11Exception ex) {
                    System.out.println("PKCS11Exception");
                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                }
                catch(RuntimeException rex) {
                    System.out.println("RuntimeException");
                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, rex);
                }
            }
            return result;
        }

        
        public  X509Certificate[]  getSignatureCertificateChain()  throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, InvalidKeyException, PKCS11Exception,
			SignatureException {
             if(this.pkcs11 ==null)
            {
                try {
                    if(!isEidPresent() ) {
                        return null;
                    }
                 } catch (Exception ex) {
                    System.out.println("Exception "+ex.getMessage());
                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            if(this.pkcs11 != null) {

                X509Certificate certificate = null;
                long session  = this.pkcs11.C_OpenSession(this.slotIdx, PKCS11Constants.CKF_SERIAL_SESSION, null, null);
                try {
                        be.fedict.eid.applet.Dialogs dialogs = new Dialogs(this.view, this.messages);
                        char[] pin = dialogs.getPin();

                        this.pkcs11.C_Login(session, PKCS11Constants.CKU_USER, pin);

                        CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[2];
                        attributes[0] = new CK_ATTRIBUTE();
                        attributes[0].type = PKCS11Constants.CKA_CLASS;
                        attributes[0].pValue = PKCS11Constants.CKO_CERTIFICATE;
                        attributes[1] = new CK_ATTRIBUTE();
                        attributes[1].type = PKCS11Constants.CKA_LABEL;
                        attributes[1].pValue = getSignatureLabel().getBytes("UTF-8");
                        this.pkcs11.C_FindObjectsInit(session, attributes);

                        this.view.addDetailMessage(getAuthenticationLabel());
                        this.view.addDetailMessage(getSignatureLabel());
                        try {
                                long[] certHandles = this.pkcs11.C_FindObjects(session, 1);
                                if (0 == certHandles.length) {
                                        this.view.addDetailMessage("no PKCS#11 key handle for label: "+getSignatureLabel());
                                        throw new RuntimeException("cannot sign via PKCS#11");
                                }
                                if(certHandles.length == 1) {

                                    CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
                                    template[0] = new CK_ATTRIBUTE();
                                    template[0].type = PKCS11Constants.CKA_VALUE;
                                    this.pkcs11.C_GetAttributeValue(session, certHandles[0], template);
                                    byte[] certBytes = (byte[]) template[0].pValue;
                                    if(certBytes != null) {
                                        certificate = new X509CertImpl(certBytes);
                                        //this.view.addDetailMessage("X509Certificate : " + certificate.getSerialNumber().toString());
                                        //this.view.addDetailMessage("X509Principal name : " + certificate.getIssuerX500Principal().toString());
                                        //this.view.addDetailMessage("X509Certificate : " + certificate.toString());
                                    }
                                }
                        } finally {
                                this.pkcs11.C_FindObjectsFinal(session);
                        }
                        if(certificate != null) {
                                /*this.signCertificateChain = new LinkedList<X509Certificate>();
                                this.signCertificateChain.add(certificate);
                                //this.view.addDetailMessage("X509Certificate certificate : " + certificate.toString());
                                X509Certificate certificateSINPE =  getIssuerCert(child_childCACertificate) ;
                                this.signCertificateChain.add(certificateSINPE);
                                //this.view.addDetailMessage("X509Certificate certificateSINPE : " + certificateSINPE.toString());
                                X509Certificate certificatePOLITICA =  getIssuerCert(childCACertificate) ;
                                this.signCertificateChain.add(certificatePOLITICA);
                                //this.view.addDetailMessage("X509Certificate certificatePOLITICA : " + certificatePOLITICA.toString());
                                X509Certificate rootCerti =  getIssuerCert(rootCACertificate) ;
                                this.signCertificateChain.add(rootCerti);
                                //this.view.addDetailMessage("X509Certificate ROOT : " + rootCerti.toString());*/
                                buildCertificatePath(this.signCertificateChain, certificate);
                  }

                } catch (PKCS11Exception ex) {
                    System.out.println("PKCS11Exception");
                    //Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                }
                catch(RuntimeException rex) {
                    System.out.println("RuntimeException");
                    //Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, rex);
                    if("operation canceled.".equals(rex.getMessage())) {
                        throw new IOException("El usuario ha cancelado el proceso.");
                    }
                     else {
                        throw new IOException(rex.getMessage());
                     }
                }
                finally {
                    this.pkcs11.C_CloseSession(session);
                }
            }
             X509Certificate[] resultChain = new X509Certificate[signCertificateChain.size()];
            signCertificateChain.toArray(resultChain);
            return resultChain;

        }
        public byte[] signAuthentication(byte[] toBeSigned) throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, InvalidKeyException, PKCS11Exception,
			SignatureException {
            if(this.pkcs11 ==null)
            {
                try {
                    if(!isEidPresent() ) {
                        return null;
                    }
                 } catch (Exception ex) {
                    System.out.println("Exception "+ex.getMessage());
                    Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            if(this.pkcs11 != null) {

                X509Certificate certificate = null;
                long session  = this.pkcs11.C_OpenSession(this.slotIdx, PKCS11Constants.CKF_SERIAL_SESSION, null, null);
                try {
                        be.fedict.eid.applet.Dialogs dialogs = new Dialogs(this.view, this.messages);
                        char[] pin = dialogs.getPin();
                        
                        this.pkcs11.C_Login(session, PKCS11Constants.CKU_USER, pin);

                        CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[2];
                        attributes[0] = new CK_ATTRIBUTE();
                        attributes[0].type = PKCS11Constants.CKA_CLASS;
                        attributes[0].pValue = PKCS11Constants.CKO_CERTIFICATE;
                        attributes[1] = new CK_ATTRIBUTE();
                        attributes[1].type = PKCS11Constants.CKA_LABEL;
                        attributes[1].pValue = getAuthenticationLabel().getBytes("UTF-8");
                        this.pkcs11.C_FindObjectsInit(session, attributes);
                        
                        this.view.addDetailMessage(getAuthenticationLabel());
                        this.view.addDetailMessage(getSignatureLabel());
                        try {
                                long[] certHandles = this.pkcs11.C_FindObjects(session, 1);
                                if (0 == certHandles.length) {
                                        /*
                                         * In case of OpenSC PKCS#11.
                                         */
                                        this.view.addDetailMessage("no PKCS#11 key handle for label: "+getAuthenticationLabel());
                                        throw new RuntimeException("cannot sign via PKCS#11");
                                }
                                if(certHandles.length == 1) {
                                    
                                    CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
                                    template[0] = new CK_ATTRIBUTE();
                                    template[0].type = PKCS11Constants.CKA_VALUE;
                                    this.pkcs11.C_GetAttributeValue(session, certHandles[0], template);
                                    byte[] certBytes = (byte[]) template[0].pValue;
                                    if(certBytes != null) {
                                        certificate = new X509CertImpl(certBytes);
                                        //this.view.addDetailMessage("X509Certificate : " + certificate.getSerialNumber().toString());
                                        //this.view.addDetailMessage("X509Principal name : " + certificate.getIssuerX500Principal().toString());
                                        //this.view.addDetailMessage("X509Certificate : " + certificate.toString());
                                    }
                                }
                        } finally {
                                this.pkcs11.C_FindObjectsFinal(session);
                        }
                        if(certificate != null) {
                            /*
                                this.authnCertificateChain = new LinkedList<X509Certificate>();
                                this.authnCertificateChain.add(certificate);
                                X509Certificate certificateSINPE =  getIssuerCert(child_childCACertificate) ;
                                this.authnCertificateChain.add(certificateSINPE);
                               // this.view.addDetailMessage("X509Certificate ISSUER : " + certi.toString());
                                X509Certificate certificatePOLITICA =  getIssuerCert(childCACertificate) ;
                                this.authnCertificateChain.add(certificatePOLITICA);
                                X509Certificate rootCerti =  getIssuerCert(rootCACertificate) ;
                                this.authnCertificateChain.add(rootCerti);
                                //this.view.addDetailMessage("X509Certificate ROOT : " + rootCerti.toString());
                                */

                                buildCertificatePath(this.authnCertificateChain, certificate);

                                attributes = new CK_ATTRIBUTE[2];
                                attributes[0] = new CK_ATTRIBUTE();
                                attributes[0].type = PKCS11Constants.CKA_CLASS;
                                attributes[0].pValue = PKCS11Constants.CKO_PRIVATE_KEY;
                                attributes[1] = new CK_ATTRIBUTE();
                                attributes[1].type = PKCS11Constants.CKA_LABEL;
                                attributes[1].pValue = getAuthenticationLabel().getBytes("UTF-8");
                                this.pkcs11.C_FindObjectsInit(session, attributes);
                                long keyHandle = -1;

                                try {
                                        long[] keyHandles = this.pkcs11.C_FindObjects(session, 1);
                                        if (0 == keyHandles.length) {
                                                
                                                this.view.addDetailMessage("no PKCS#11 key handle for label: "+getAuthenticationLabel());
                                                throw new RuntimeException("cannot sign via PKCS#11");
                                        }
                                        if(keyHandles.length == 1) {
                                            keyHandle = keyHandles[0];
                                        }
                                } finally {
                                        this.pkcs11.C_FindObjectsFinal(session);
                                }
                                if(keyHandle != -1) {
                                    CK_MECHANISM mechanism = new CK_MECHANISM();
                                    mechanism.mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
                                    mechanism.pParameter = null;
                                    this.pkcs11.C_SignInit(session, mechanism, keyHandle);
                                    ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
                                    digestInfo.write(Constants.SHA1_DIGEST_INFO_PREFIX);
                                    digestInfo.write(toBeSigned);
                                    byte[] signatureValue = pkcs11.C_Sign(session, toBeSigned);
                                    return signatureValue;
                                }
                        }

                } catch (PKCS11Exception ex) {
                    System.out.println("PKCS11Exception");
                    //Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                }
                catch(RuntimeException rex) {
                    System.out.println("RuntimeException");
                    //Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, rex);
                    if("operation canceled.".equals(rex.getMessage())) {
                        throw new IOException("El usuario ha cancelado el proceso.");
                    }
                     else {
                        throw new IOException(rex.getMessage());
                     }
                }
                finally {
                    this.pkcs11.C_CloseSession(session);
                }
            }
            return null;
	}

        public String getAuthenticationLabel() {
            return authenticationLabel;
        }

        public void setAuthenticationLabel(String authenticationLabel) {
            this.authenticationLabel = authenticationLabel;
        }

        public String getSignatureLabel() {
            return signatureLabel;
        }

        public void setSignatureLabel(String signatureLabel) {
            this.signatureLabel = signatureLabel;
        }

	public List<X509Certificate> getAuthnCertificateChain() {
		return this.authnCertificateChain;
	}

	public List<X509Certificate> getSignCertificateChain() {
		return this.signCertificateChain;
	}

	public void close() throws PKCS11Exception, NoSuchFieldException,
			IllegalAccessException {
		cFinalize();
	}

	public void removeCard() throws PKCS11Exception, InterruptedException {
		while (true) {
			CK_SLOT_INFO slotInfo = this.pkcs11.C_GetSlotInfo(this.slotIdx);
			if ((slotInfo.flags & PKCS11Constants.CKF_TOKEN_PRESENT) == 0) {
				return;
			}
			/*
			 * We want to be quite responsive here.
			 */
			Thread.sleep(100);
		}
	}

	public byte[] sign(byte[] digestValue, String digestAlgo) throws Exception {
		/*
		 * We sign directly via the PKCS#11 wrapper since this is the only way
		 * to sign the given digest value.
		 */
                 if(this.pkcs11 ==null)
                {
                    try {
                        if(!isEidPresent() ) {
                            return null;
                        }
                     } catch (Exception ex) {
                        System.out.println("Exception "+ex.getMessage());
                        Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
		long session = this.pkcs11.C_OpenSession(this.slotIdx,
				PKCS11Constants.CKF_SERIAL_SESSION, null, null);
		byte[] signatureValue = null;
		try {
                        be.fedict.eid.applet.Dialogs dialogs = new Dialogs(this.view, this.messages);
                        char[] pin = dialogs.getPin();

                        this.pkcs11.C_Login(session, PKCS11Constants.CKU_USER, pin);

			CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[2];
			attributes[0] = new CK_ATTRIBUTE();
			attributes[0].type = PKCS11Constants.CKA_CLASS;
			attributes[0].pValue = PKCS11Constants.CKO_PRIVATE_KEY;
			attributes[1] = new CK_ATTRIBUTE();
			attributes[1].type = PKCS11Constants.CKA_LABEL;
			attributes[1].pValue = getSignatureLabel().getBytes("UTF-8");
			this.pkcs11.C_FindObjectsInit(session, attributes);
			long keyHandle =  -1 ;
			try {
				long[] keyHandles = this.pkcs11.C_FindObjects(session, 1);
				if (0 == keyHandles.length) {
					/*
					 * In case of OpenSC PKCS#11.
					 */
					this.view.addDetailMessage("no PKCS#11 key handle for label:  "+ getSignatureLabel());
					throw new RuntimeException("cannot sign via PKCS#11");
				}
				if(keyHandles.length == 1) {
                                            keyHandle = keyHandles[0];
                                 }
			} finally {
				this.pkcs11.C_FindObjectsFinal(session);
			}

                        if(keyHandle != -1) {
                            CK_MECHANISM mechanism = new CK_MECHANISM();
                            mechanism.mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
                            mechanism.pParameter = null;
                            this.pkcs11.C_SignInit(session, mechanism, keyHandle);
                            ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
                            digestInfo.write(Constants.SHA1_DIGEST_INFO_PREFIX);
                            digestInfo.write(digestValue);
                            signatureValue = pkcs11.C_Sign(session, digestValue);

                        }

		} 
                catch(RuntimeException rex) {
                     System.out.println("RuntimeException");
                    //Logger.getLogger(Pkcs11Eid.class.getName()).log(Level.SEVERE, null, rex);
                    if("operation canceled.".equals(rex.getMessage())) {
                        throw new IOException("El usuario ha cancelado el proceso.");
                    }
                     else {
                        throw new IOException(rex.getMessage());
                     }
                }
                finally {
			this.pkcs11.C_CloseSession(session);
		}

                //The certificate path is already built  and stored in "this.signCertificateChain"
	
		return signatureValue;
	}

	public void diagnosticTests(
			DiagnosticCallbackHandler diagnosticCallbackHandler) {
		String pkcs11Path;
		try {
			pkcs11Path = getPkcs11Path();
		} catch (PKCS11NotFoundException e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.PKCS11_AVAILABLE, false, null);
			return;
		}
		diagnosticCallbackHandler.addTestResult(
				DiagnosticTests.PKCS11_AVAILABLE, true, pkcs11Path);

		try {
			this.pkcs11 = loadPkcs11(pkcs11Path);
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.PKCS11_RUNTIME, false, e.getMessage());
			return;
		}

		CK_INFO ck_info;
		try {
			ck_info = this.pkcs11.C_GetInfo();
		} catch (PKCS11Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.PKCS11_RUNTIME, false, e.getMessage());
			return;
		}
		String libraryDescription = new String(ck_info.libraryDescription)
				.trim();
		this.view
				.addDetailMessage("library description: " + libraryDescription);
		String manufacturerId = new String(ck_info.manufacturerID).trim();
		this.view.addDetailMessage("manufacturer ID: " + manufacturerId);
		String libraryVersion = Integer.toString(ck_info.libraryVersion.major,
				16)
				+ "." + Integer.toString(ck_info.libraryVersion.minor, 16);
		this.view.addDetailMessage("library version: " + libraryVersion);
		String cryptokiVersion = Integer.toString(
				ck_info.cryptokiVersion.major, 16)
				+ "." + Integer.toString(ck_info.cryptokiVersion.minor, 16);
		this.view.addDetailMessage("cryptoki version: " + cryptokiVersion);
		String pkcs11Information = libraryDescription + ", " + manufacturerId
				+ ", " + libraryVersion + ", " + cryptokiVersion;

		diagnosticCallbackHandler.addTestResult(DiagnosticTests.PKCS11_RUNTIME,
				true, pkcs11Information);
	}
}

