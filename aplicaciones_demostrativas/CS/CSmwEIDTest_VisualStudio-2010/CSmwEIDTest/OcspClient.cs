
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;


namespace CSmwEIDTest
{

public enum CertificateStatus { Good = 0, Revoked = 1, Unknown = 2 };

    class X509TestPublicKeyCertificate : X509Certificate
    {
        public X509TestPublicKeyCertificate(X509CertificateStructure in_Cert)
            : base(in_Cert)
        {
        }
    }

    class OcspClient
    {

        public readonly int BufferSize = 4096 * 8;
        private readonly int MaxClockSkew = 36000000;

        private X509TestPublicKeyCertificate m_PublicKeyCertificate = null;
        public X509TestPublicKeyCertificate PublicKeyCertificate
        {
            get
            {
                return m_PublicKeyCertificate;
            }
        }

        public X509Certificate LeerCertificado(String in_Filename)
        {
            X509CertificateParser certParser = new X509CertificateParser();

            Stream stream = new FileStream(in_Filename, FileMode.Open);
            X509Certificate certificado = certParser.ReadCertificate(stream);
            stream.Close();

            return certificado;
        }

        public OcspClient(byte[] in_CertificateInput)
        {
            X509CertificateParser certParser = new X509CertificateParser();
            X509Certificate certificado = (X509Certificate)certParser.ReadCertificate(in_CertificateInput);
            m_PublicKeyCertificate = new X509TestPublicKeyCertificate(certificado.CertificateStructure);

        }

        public CertificateStatus ConsultarEstadoDeCertificado(X509Certificate in_Certificado, X509Certificate in_CertificadoEmisor)
        {
            List<string> urls = GetAuthorityInformationAccessOcspUrl(in_Certificado);

            if (urls.Count == 0)
            {
                throw new Exception("No se encontro ningun OCSP url en el certificado.");
            }

            string url = urls[0];

            Console.WriteLine("Consultando '" + url + "'...");

            OcspReq req = GenerarRequestOCSP(in_CertificadoEmisor, in_Certificado.SerialNumber);

            byte[] binaryResp = PostData(url, req.GetEncoded(), "application/ocsp-request", "application/ocsp-response");

            return ProcesarRespuestaOcsp(in_Certificado, in_CertificadoEmisor, binaryResp);
        }



        public byte[] PostData(string in_Url, byte[] in_Data, string in_ContentType, string in_Accept)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(in_Url);
            request.Method = "POST";
            request.ContentType = in_ContentType;
            request.ContentLength = in_Data.Length;
            request.Accept = in_Accept;
            Stream stream = request.GetRequestStream();
            stream.Write(in_Data, 0, in_Data.Length);
            stream.Close();
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream respStream = response.GetResponseStream();
            byte[] resp = ToByteArray(respStream);
            respStream.Close();

            return resp;
        }

        public byte[] ToByteArray(Stream in_Stream)
        {
            byte[] buffer = new byte[BufferSize];
            MemoryStream ms = new MemoryStream();

            int read = 0;

            while ((read = in_Stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
            }

            return ms.ToArray();
        }


        public static List<string> GetAuthorityInformationAccessOcspUrl(X509Certificate in_Certificado)
        {
            List<string> ocspUrls = new List<string>();

            try
            {
                Asn1Object obj = ObtenerValorDeExtension(in_Certificado, X509Extensions.AuthorityInfoAccess.Id);

                if (obj == null)
                {
                    return null;
                }


                Asn1Sequence s = (Asn1Sequence)obj;
                IEnumerator elementos = s.GetEnumerator();

                while (elementos.MoveNext())
                {
                    Asn1Sequence elemento = (Asn1Sequence)elementos.Current;
                    DerObjectIdentifier oid = (DerObjectIdentifier)elemento[0];

                    if (oid.Id.Equals("1.3.6.1.5.5.7.48.1")) // Ocsp?
                    {
                        Asn1TaggedObject objetoTagged = (Asn1TaggedObject)elemento[1];
                        GeneralName gn = (GeneralName)GeneralName.GetInstance(objetoTagged);
                        ocspUrls.Add(((DerIA5String)DerIA5String.GetInstance(gn.Name)).GetString());
                    }
                }
            }
            catch (Exception e)
            {
                throw new Exception("Error en AuthorityInformationAccess.", e);
            }

            return ocspUrls;
        }

        protected static Asn1Object ObtenerValorDeExtension(X509Certificate in_Certificado,
                string oid)
        {
            if (in_Certificado == null)
            {
                return null;
            }

            byte[] bytes = in_Certificado.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

            if (bytes == null)
            {
                return null;
            }

            Asn1InputStream aIn = new Asn1InputStream(bytes);

            return aIn.ReadObject();
        }


        private CertificateStatus ProcesarRespuestaOcsp(X509Certificate in_Certificado, X509Certificate in_CertificadoEmisor, byte[] in_BytesRespuesta)
        {
            OcspResp r = new OcspResp(in_BytesRespuesta);
            CertificateStatus estado = CertificateStatus.Unknown;

            switch (r.Status)
            {
                case OcspRespStatus.Successful:
                    BasicOcspResp or = (BasicOcspResp)r.GetResponseObject();


                    if (or.Responses.Length == 1)
                    {
                        SingleResp resp = or.Responses[0];

                        ValidarCertificateId(in_CertificadoEmisor, in_Certificado, resp.GetCertID());
                        Object estadoCertificado = resp.GetCertStatus();

                        if (estadoCertificado == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                        {
                            estado = CertificateStatus.Good;
                        }
                        else if (estadoCertificado is Org.BouncyCastle.Ocsp.RevokedStatus)
                        {
                            estado = CertificateStatus.Revoked;
                        }
                        else if (estadoCertificado is Org.BouncyCastle.Ocsp.UnknownStatus)
                        {
                            estado = CertificateStatus.Unknown;
                        }
                    }
                    break;
                default:
                    throw new Exception("Status desconocido'" + r.Status + "'.");
            }

            return estado;
        }

        private void ValidateResponse(BasicOcspResp in_OcspResp, X509Certificate in_CertificadoEmisor)
        {
            ValidarResponseSignature(in_OcspResp, in_CertificadoEmisor.GetPublicKey());
            ValidarSignerAuthorization(in_CertificadoEmisor, in_OcspResp.GetCerts()[0]);
        }


        private void ValidarSignerAuthorization(X509Certificate in_CertificadoEmisor, X509Certificate in_CertificadoFirmante)
        {

            if (!(in_CertificadoEmisor.IssuerDN.Equivalent(in_CertificadoFirmante.IssuerDN) && in_CertificadoEmisor.SerialNumber.Equals(in_CertificadoFirmante.SerialNumber)))
            {
                throw new Exception("OCSP signer Invalido");
            }
        }

        private void ValidarResponseSignature(BasicOcspResp in_OcspResp, Org.BouncyCastle.Crypto.AsymmetricKeyParameter in_PublicKey)
        {
            if (!in_OcspResp.Verify(in_PublicKey))
            {
                throw new Exception("Firma OCSP Invalida");
            }
        }


        private void ValidarCertificateId(X509Certificate in_CertificadoEmisor, X509Certificate in_Certificado, CertificateID in_IDCertificado)
        {
            CertificateID idEsperado = new CertificateID(CertificateID.HashSha1, in_CertificadoEmisor, in_Certificado.SerialNumber);

            if (!idEsperado.SerialNumber.Equals(in_IDCertificado.SerialNumber))
            {
                throw new Exception("ID de Certificado invalido");
            }

            if (!Org.BouncyCastle.Utilities.Arrays.AreEqual(idEsperado.GetIssuerNameHash(), in_IDCertificado.GetIssuerNameHash()))
            {
                throw new Exception("Certificado Emisor invalido");
            }

        }

        private OcspReq GenerarRequestOCSP(X509Certificate in_CertificadoEmisor, BigInteger in_NumeroSerie)
        {
            CertificateID id = new CertificateID(CertificateID.HashSha1, in_CertificadoEmisor, in_NumeroSerie);
            return GenerarRequestOCSP(id);
        }

        private OcspReq GenerarRequestOCSP(CertificateID in_Id)
        {
            OcspReqGenerator ocspRequestGenerador = new OcspReqGenerator();

            ocspRequestGenerador.AddRequest(in_Id);

            BigInteger nonce = BigInteger.ValueOf(new DateTime().Ticks);

            ArrayList oids = new ArrayList();
            Hashtable valores = new Hashtable();

            oids.Add(OcspObjectIdentifiers.PkixOcsp);

            Asn1OctetString asn1 = new DerOctetString(new DerOctetString(new byte[] { 1, 3, 6, 1, 5, 5, 7, 48, 1, 1 }));

            valores.Add(OcspObjectIdentifiers.PkixOcsp, new X509Extension(false, asn1));
            ocspRequestGenerador.SetRequestExtensions(new X509Extensions(oids, valores));

            return ocspRequestGenerador.Generate();
        }
    }
} 
