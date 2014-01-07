package javamweidtest;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.*;
import java.util.*;

class EncryptedData {
    private byte[] m_EncryptedData;
    public void SetBytes(byte[] in_bytes)
    {
        m_EncryptedData = in_bytes;
    }
    public String ToString()
    {
        if(m_EncryptedData == null) {
            return "";
        }
        return new String(m_EncryptedData);
    }
}


public class PKCS11Controller {

    private String m_FileName;
    private String m_AutenticacionLabel = "NOT_SET";
    private String m_SignLabel = "NOT_SET";
    private String m_IssuerCertificate = "NOT_SET";
    private Module m_Module = null;
    private Slot[] m_Slots = null;
    private int m_CurrentIndex = -1;

    public PKCS11Controller(String in_FileName) {
        m_FileName = in_FileName;
    }

    public List<String> GetReadersList(boolean in_Refresh) {
        //List<String> readers = new LinkedList<>(); //jdk7
    	List<String> readers = new LinkedList<String>(); //jdk6
        try {
            if (m_Module == null) {
                m_Module = Module.getInstance(m_FileName);
                m_Module.initialize(null);
            }

            if (m_Slots == null) {
                // GetSlotList.
                m_Slots = m_Module.getSlotList(true);
            } else if (in_Refresh) {
                //TODO verify
                //m_Slots = m_Module.GetSlotList(true);
            }
            for (Slot slot : m_Slots) {
                readers.add(slot.getSlotInfo().getSlotDescription());
                System.out.println(slot.getSlotInfo().getSlotDescription());
            }
        } 
        catch (IOException e) {
            System.out.println(e);
        }
        catch (TokenException e) {
            System.out.println(e);
        }
        return readers;
    }

    public boolean NumeroTarjetaValida(int in_SlotIndex, String in_NumeroTarjeta) {
        boolean result = false;
        if (m_Slots.length > in_SlotIndex) {
            try {
                Slot slot = m_Slots[in_SlotIndex];
                result = slot.getToken().getTokenInfo().getSerialNumber().matches(in_NumeroTarjeta);
            } catch (TokenException ex) {
                System.out.println(ex);
            }
        }
        return result;
    }

    public boolean Login(int in_SlotIndex, String in_PIN) {
        boolean result = false;
        try {
            if (m_Module == null) {
                m_Module = Module.getInstance(m_FileName);
                m_Module.initialize(null);
            }

            if (m_Slots == null) {
                // GetSlotList.
                m_Slots = m_Module.getSlotList(true);
            }
            if (m_Slots.length > in_SlotIndex) {
                Slot slot = m_Slots[in_SlotIndex];
                Session session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                        Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                m_CurrentIndex = in_SlotIndex;
                session.login(Session.UserType.USER, in_PIN.toCharArray());

                try {

                    GenericTemplate certificateSearchTemplate = new GenericTemplate();
                    LongAttribute objectClassAttribute = new LongAttribute(PKCS11Constants.CKA_CLASS);
                    objectClassAttribute.setLongValue(new Long(PKCS11Constants.CKO_CERTIFICATE));
                    certificateSearchTemplate.addAttribute(objectClassAttribute);
                    LongAttribute certificateTypeAttribute = new LongAttribute(PKCS11Constants.CKA_CERTIFICATE_TYPE);
                    certificateTypeAttribute.setLongValue(new Long(PKCS11Constants.CKC_X_509));
                    certificateSearchTemplate.addAttribute(certificateTypeAttribute);


                    session.findObjectsInit(certificateSearchTemplate);
                    //P11Object
                    iaik.pkcs.pkcs11.objects.Object[] certificates = session.findObjects(2);
                    if (certificates.length == 2) {
                        SetAutenticacionLabel(new String(((X509PublicKeyCertificate) certificates[0]).getLabel().getCharArrayValue()));
                        SetSignatureLabel(new String(((X509PublicKeyCertificate) certificates[1]).getLabel().getCharArrayValue()));
                    }

                    session.findObjectsFinal();
                    ///////////////////
                    result = true;
                } finally {
                    // Log out.
                    session.logout();
                }
            }
        } 
        catch (IOException e) {
            System.out.println(e);
        }
        catch (TokenException e) {
            System.out.println(e);
        }
        return result;
    }

    public boolean Firmar(int in_SlotIndex, String in_PIN, byte[] in_Data, EncryptedData out_encryptedData) {
        boolean result = false;
        out_encryptedData.SetBytes(null);
        try {
            if (m_Module == null) {
                m_Module = Module.getInstance(m_FileName);
                m_Module.initialize(null);
            }

            if (m_Slots == null) {
                // GetSlotList.
                m_Slots = m_Module.getSlotList(true);
            }
            if (m_Slots.length > in_SlotIndex) {
                Slot slot = m_Slots[in_SlotIndex];
                Session session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                        Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                m_CurrentIndex = in_SlotIndex;
                session.login(Session.UserType.USER, in_PIN.toCharArray());

                try {

                    GenericTemplate privateKeySearchTemplate = new GenericTemplate();
                    LongAttribute classAttribute = new LongAttribute(PKCS11Constants.CKA_CLASS);
                    classAttribute.setLongValue(new Long(PKCS11Constants.CKO_PRIVATE_KEY));
                    privateKeySearchTemplate.addAttribute(classAttribute);

                    ByteArrayAttribute keyLabelAttribute = new ByteArrayAttribute(PKCS11Constants.CKA_LABEL);
                    
                    byte[] label = m_SignLabel.getBytes("UTF-8");
                    
                    keyLabelAttribute.setByteArrayValue(label);
                    privateKeySearchTemplate.addAttribute(keyLabelAttribute);

                    session.findObjectsInit(privateKeySearchTemplate);

                    iaik.pkcs.pkcs11.objects.Object[] privatekeys = session.findObjects(1);

                    session.findObjectsFinal();

                    if (privatekeys.length >= 1) {
                        
                        iaik.pkcs.pkcs11.Mechanism signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
                        // initialize for signing
                        session.signInit(signatureMechanism, (Key) privatekeys[0]);                        
                        
                        out_encryptedData.SetBytes(session.sign(in_Data));
                    }
                    result = true;
                } finally {
                    // Log out.
                    session.logout();
                }
            }
        } 
        catch (IOException e) {
            System.out.println(e);
        }
        catch (TokenException e) {
            System.out.println(e);
        }
        return result;

    }

    void SetAutenticacionLabel(String in_AuthenticationLabel) {
        m_AutenticacionLabel = in_AuthenticationLabel;
    }

    void SetSignatureLabel(String in_SignLabel) {
        m_SignLabel = in_SignLabel;
    }

    void SetIssuerCertificate(String in_IssuerCertificate) {
        m_IssuerCertificate = in_IssuerCertificate;
    }

    String GetTokenInfo(int in_SlotIndex) {
        if (m_Slots.length > in_SlotIndex) {
            try {
                Slot slot = m_Slots[in_SlotIndex];
                StringBuilder builder = new StringBuilder();
                builder.append("ManufacturerID: ");
                builder.append(slot.getToken().getTokenInfo().getManufacturerID());
                builder.append("\n");
                builder.append("Label: ");
                builder.append(slot.getToken().getTokenInfo().getLabel());
                builder.append("\n");
                builder.append("HardwareVersion: ");
                builder.append(slot.getToken().getTokenInfo().getHardwareVersion().toString());
                builder.append("\n");
                builder.append("FirmwareVersion: ");
                builder.append(slot.getToken().getTokenInfo().getFirmwareVersion().toString());
                builder.append("\n");
                builder.append("Model: ");
                builder.append(slot.getToken().getTokenInfo().getModel());
                return builder.toString();
            } catch (TokenException ex) {
                System.out.println(ex);
            }
        }
        return "";
    }

    boolean Autenticar(int in_SlotIndex, String in_PIN, StringBuilder out_Error) {
        boolean result = false;

        try {
            if (m_Module == null) {
                m_Module = Module.getInstance(m_FileName);
                m_Module.initialize(null);
            }

            if (m_Slots == null) {
                // GetSlotList.
                m_Slots = m_Module.getSlotList(true);
            }
            if (m_Slots.length > in_SlotIndex) {
                Slot slot = m_Slots[in_SlotIndex];
                Session session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                        Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                m_CurrentIndex = in_SlotIndex;
                session.login(Session.UserType.USER, in_PIN.toCharArray());

                try {
                    
                    GenericTemplate certificateSearchTemplate = new GenericTemplate();
                    LongAttribute classAttribute = new LongAttribute(PKCS11Constants.CKA_CLASS);
                    classAttribute.setLongValue(new Long(PKCS11Constants.CKO_CERTIFICATE));
                    certificateSearchTemplate.addAttribute(classAttribute);
                    
                    LongAttribute certificateTypeAttribute = new LongAttribute(PKCS11Constants.CKA_CERTIFICATE_TYPE);
                    certificateTypeAttribute.setLongValue(new Long(PKCS11Constants.CKC_X_509));
                    certificateSearchTemplate.addAttribute(certificateTypeAttribute);
                    
                    ByteArrayAttribute keyLabelAttribute = new ByteArrayAttribute(PKCS11Constants.CKA_LABEL);
                    
                    byte[] label = m_AutenticacionLabel.getBytes("UTF-8");
                    
                    keyLabelAttribute.setByteArrayValue(label);
                    certificateSearchTemplate.addAttribute(keyLabelAttribute);

                    session.findObjectsInit(certificateSearchTemplate);

                    iaik.pkcs.pkcs11.objects.Object[] certificates = session.findObjects(1);

                    session.findObjectsFinal();

                    if (certificates.length >= 1) {
                        
                        X509PublicKeyCertificate cert = (X509PublicKeyCertificate) certificates[0];
                        OcspClient oscpClient = new OcspClient(cert.getValue().getByteArrayValue());
                        try {
                            oscpClient.getPublicKeyCertificate().checkValidity();
                            CertificateStatus status = oscpClient.consultarEstadoDeCertificado(oscpClient.getPublicKeyCertificate(), oscpClient.leerCertificado(m_IssuerCertificate));
                            if (status == CertificateStatus.Good) {
                                out_Error.append("OK");
                                result = true;
                            } else if (status == CertificateStatus.Revoked) {
                                out_Error.append("Certificado Revocado");
                            } else {
                                out_Error.append("Certificado/Respuesta Desconocido(s)");
                            }
                        }
                        catch(Exception ex) {
                            System.out.println(ex);
                            out_Error.append( ex.getMessage());
                        }
                    } else {
                        out_Error.append( "No se encontraron objetos en la tarjeta.");
                    }


                } catch (UnsupportedEncodingException  e) {
                    System.out.println(e);
                    out_Error.append( e.getMessage());
                }
                catch (TokenException e) {
                    System.out.println(e);
                    out_Error.append( e.getMessage());
                } 
                finally {
                    // Log out.
                    session.logout();
                }
            }
        } 
        catch (IOException e) {
            System.out.println(e);
        }
        catch (TokenException e) {
            System.out.println(e);
        }
        return result;
    }
}

