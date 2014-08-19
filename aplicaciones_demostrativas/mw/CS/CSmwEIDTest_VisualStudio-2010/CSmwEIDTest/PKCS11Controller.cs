using System;
using System.Collections.Generic;

using System.Text;

using System.Runtime.InteropServices;

using Net.Sf.Pkcs11;
using Net.Sf.Pkcs11.Objects;
using Net.Sf.Pkcs11.Wrapper;

using System.Security.Cryptography.X509Certificates;
using System.IO;


namespace CSmwEIDTest
{
    class PKCS11Controller
    {
        private String m_FileName;
        private String m_AutenticacionLabel = "NOT_SET";
        private String m_SignLabel = "NOT_SET";
        private String m_IssuerCertificate = "NOT_SET";

        private Module m_Module = null;
        private Slot[] m_Slots = null;
        private int m_CurrentIndex = -1;
        public PKCS11Controller(String in_FileName)
        {
            m_FileName = in_FileName;
        }
        public List<String> GetReadersList(bool in_Refresh = false)
        {
            List<String> readers = new List<string>();
            try
            {
                if (m_Module == null)
                {
                    m_Module = Module.GetInstance(m_FileName);
                }

                if (m_Slots == null)
                {
                    // GetSlotList.
                    m_Slots = m_Module.GetSlotList(true);
                }
                else if (in_Refresh)
                {
                    //TODO verify
                    //m_Slots = m_Module.GetSlotList(true);
                }
                foreach (Slot slot in m_Slots)
                {
                    readers.Add(slot.SlotInfo.SlotDescription);
                    Console.WriteLine(slot.SlotInfo.SlotDescription);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return readers;
        }

        internal bool NumeroTarjetaValida(int in_SlotIndex, string in_NumeroTarjeta)
        {
            bool result = false;
            if (m_Slots.Length > in_SlotIndex)
            {
                Slot slot = m_Slots[in_SlotIndex];
                result = slot.Token.TokenInfo.SerialNumber == in_NumeroTarjeta;
            }
            return result;
        }

        internal bool Login(int in_SlotIndex, string in_PIN)
        {
            bool result = false;
            try
            {
                if (m_Module == null)
                {
                    m_Module = Module.GetInstance(m_FileName);
                }

                if (m_Slots == null)
                {
                    // GetSlotList.
                    m_Slots = m_Module.GetSlotList(true);
                }
                if (m_Slots.Length > in_SlotIndex)
                {
                    Slot slot = m_Slots[in_SlotIndex];
                    Session session = slot.Token.OpenSession(false);
                    m_CurrentIndex = in_SlotIndex;
                    session.Login(UserType.USER, in_PIN);

                    try
                    {

                        ObjectClassAttribute classAttribute = new ObjectClassAttribute(CKO.CERTIFICATE);
                        //ByteArrayAttribute keyLabelAttribute = new ByteArrayAttribute(CKA.LABEL);
                        //keyLabelAttribute.Value = System.Text.Encoding.UTF8.GetBytes(m_SignLabel);

                        session.FindObjectsInit(new P11Attribute[] {
                                 classAttribute
                          //       keyLabelAttribute
                                }
                                );
                        P11Object[] certificates = session.FindObjects(2) as P11Object[];
                        if (certificates.Length == 2)
                        {
                            SetAutenticacionLabel(new string(((X509PublicKeyCertificate)certificates[0]).Label.Value));
                            SetSignatureLabel(new string(((X509PublicKeyCertificate)certificates[1]).Label.Value));
                        }
                        
                        session.FindObjectsFinal();

                        ///////////////////
                        result = true;
                    }
                    finally
                    {
                        // Log out.
                        session.Logout();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return result;
        }



        internal bool Firmar(int in_SlotIndex, string in_PIN, byte[] in_Data, out byte[] out_encryptedData)
        {
            bool result = false;
            out_encryptedData = null;
            try
            {
                if (m_Module == null)
                {
                    m_Module = Module.GetInstance(m_FileName);
                }

                if (m_Slots == null)
                {
                    // GetSlotList.
                    m_Slots = m_Module.GetSlotList(true);
                }
                if (m_Slots.Length > in_SlotIndex)
                {
                    Slot slot = m_Slots[in_SlotIndex];
                    Session session = slot.Token.OpenSession(false);
                    m_CurrentIndex = in_SlotIndex;
                    session.Login(UserType.USER, in_PIN);

                    try
                    {
                        ObjectClassAttribute classAttribute = new ObjectClassAttribute(CKO.PRIVATE_KEY);
                        ByteArrayAttribute keyLabelAttribute = new ByteArrayAttribute(CKA.LABEL);
                        keyLabelAttribute.Value = System.Text.Encoding.UTF8.GetBytes(m_SignLabel);

                        session.FindObjectsInit(new P11Attribute[] {
                                 classAttribute,
                                 keyLabelAttribute
                                }
                                );
                        P11Object[] privatekeys = session.FindObjects(1) as P11Object[];
                        session.FindObjectsFinal();

                        if (privatekeys.Length >= 1)
                        {
                            session.SignInit(new Mechanism(CKM.SHA1_RSA_PKCS), (PrivateKey)privatekeys[0]);
                            out_encryptedData = session.Sign(in_Data);
                        }
                        result = true;
                    }
                    finally
                    {
                        // Log out.
                        session.Logout();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return result;

        }

        internal void SetAutenticacionLabel(string in_AuthenticationLabel)
        {
            m_AutenticacionLabel = in_AuthenticationLabel;
        }

        internal void SetSignatureLabel(string in_SignLabel)
        {
            m_SignLabel = in_SignLabel;
        }
        internal void SetIssuerCertificate(string in_IssuerCertificate)
        {
            m_IssuerCertificate = in_IssuerCertificate;
        }
        
        internal string GetTokenInfo(int in_SlotIndex)
        {
            if (m_Slots.Length > in_SlotIndex)
            {
                Slot slot = m_Slots[in_SlotIndex];
                StringBuilder builder = new StringBuilder();
                builder.Append("ManufacturerID: ");
                builder.Append(slot.Token.TokenInfo.ManufacturerID);
                builder.AppendLine();
                builder.Append("Label: ");
                builder.Append(slot.Token.TokenInfo.Label);
                builder.AppendLine();
                builder.Append("HardwareVersion: ");
                builder.Append(slot.Token.TokenInfo.HardwareVersion.ToString());
                builder.AppendLine();
                builder.Append("FirmwareVersion: ");
                builder.Append(slot.Token.TokenInfo.FirmwareVersion.ToString());
                builder.AppendLine();
                builder.Append("Model: ");
                builder.Append(slot.Token.TokenInfo.Model);
                return builder.ToString();
            }
            return String.Empty;
        }

        internal bool Autenticar(int in_SlotIndex, string in_PIN, out string out_Error)
        {
            bool result = false;
            out_Error = "OK";

            try
            {
                if (m_Module == null)
                {
                    m_Module = Module.GetInstance(m_FileName);
                }

                if (m_Slots == null)
                {
                    // GetSlotList.
                    m_Slots = m_Module.GetSlotList(true);
                }
                if (m_Slots.Length > in_SlotIndex)
                {
                    Slot slot = m_Slots[in_SlotIndex];
                    Session session = slot.Token.OpenSession(false);
                    m_CurrentIndex = in_SlotIndex;
                    session.Login(UserType.USER, in_PIN);

                    try
                    {
                        ObjectClassAttribute certificateAttribute = new ObjectClassAttribute(CKO.CERTIFICATE);
                        ByteArrayAttribute fileLabel = new ByteArrayAttribute(CKA.LABEL);
                        fileLabel.Value = System.Text.Encoding.UTF8.GetBytes(m_AutenticacionLabel);

                        session.FindObjectsInit(new P11Attribute[] {
                                 certificateAttribute,
                                 fileLabel
                                }
                                );
                        P11Object[] foundObjects = session.FindObjects(1) as P11Object[];

                        if (foundObjects.Length == 1)
                        {
                            X509PublicKeyCertificate cert = foundObjects[0] as X509PublicKeyCertificate;
                            OcspClient oscpClient = new OcspClient(cert.Value.Encode());
                            if (oscpClient.PublicKeyCertificate.IsValidNow)
                            {
                                CertificateStatus status = oscpClient.ConsultarEstadoDeCertificado(oscpClient.PublicKeyCertificate, oscpClient.LeerCertificado(m_IssuerCertificate));
                                if (status == CertificateStatus.Good)
                                {
                                    result = true;
                                }
                                else if (status == CertificateStatus.Revoked)
                                {
                                    out_Error = "Certificado Revocado";
                                }
                                else
                                {
                                    out_Error = "Certificado Desconocido";
                                }
                            }
                            else
                            {
                                out_Error = "Certificado Expirado";
                            }
                        }
                        else
                        {
                            out_Error = "No se encontraron objetos en la tarjeta.";
                        }

                        session.FindObjectsFinal();
                        
                    }
                    catch( System.Net.WebException wex) 
                    {
                        Console.WriteLine(wex.ToString());
                        out_Error = wex.Message;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.ToString());
                        out_Error = e.Message;
                    }
                    finally
                    {
                        // Log out.
                        session.Logout();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return result;
        }
        
    }
}
