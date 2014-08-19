package com.mycompany;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.ocsp.*;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;


public class OcspClient {

    private X509Certificate m_PublicKeyCertificate;

    public X509Certificate getPublicKeyCertificate() {
        return m_PublicKeyCertificate;
    }

    public OcspClient(byte[] in_CertificateInput) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream certificateInputStream = new ByteArrayInputStream(in_CertificateInput);

            m_PublicKeyCertificate = (X509Certificate) factory.generateCertificate(certificateInputStream);

        } catch (CertificateException ex) {
            System.out.println(ex);
        }
    }

    public OcspClient(X509Certificate  in_CertificateInput) {
        try {
            m_PublicKeyCertificate = in_CertificateInput;
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }

        public X509Certificate leerCertificado(String filename)
        throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        FileInputStream stream = new FileInputStream(filename);
        X509Certificate certificado = (X509Certificate) factory.generateCertificate(stream);
        stream.close();

        return certificado;
    }

    public CertificateStatus consultarEstadoDeCertificado(X509Certificate in_Certificado, X509Certificate in_CertificadoEmisor)
            throws Exception {

        OCSPReq request = generarRequestOCSP(in_CertificadoEmisor, in_Certificado.getSerialNumber());

        List<String> locations = GetAuthorityInformationAccessOcspUrl(in_Certificado);

        for (String serviceUrl : locations) {

            SingleResp[] responses;
            try {
                OCSPResp ocspResponse = obtenerRespuestaOCSP(serviceUrl, request);
                if (OCSPRespStatus.SUCCESSFUL != ocspResponse.getStatus()) {
                    continue;
                }

                BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                responses = (basicResponse == null) ? null : basicResponse.getResponses();

            } catch (Exception e) {
                continue;
            }

            if (responses != null && responses.length == 1) {
                SingleResp resp = responses[0];
                CertificateStatus status = obtenerEstado(resp);
                return status;
            }
        }
        throw new Exception("No se puede obtener el Estado de Revocacion del Servidor OCSP.");
    }

    private CertificateStatus obtenerEstado(SingleResp resp) throws Exception {
        Object status = resp.getCertStatus();
        if (status == null) {
            return CertificateStatus.Good;
        } else if (status instanceof org.bouncycastle.ocsp.RevokedStatus) {
            return CertificateStatus.Revoked;
        } else if (status instanceof org.bouncycastle.ocsp.UnknownStatus) {
            return CertificateStatus.UNKNOWN;
        }
        return CertificateStatus.UNKNOWN;
    }

    private OCSPResp obtenerRespuestaOCSP(String ocspUrl,
            OCSPReq request) throws Exception {
        try {

            byte[] array = request.getEncoded();
            if (ocspUrl.startsWith("http")) {
                HttpURLConnection con;
                URL url = new URL(ocspUrl);
                con = (HttpURLConnection) url.openConnection();
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream out = con.getOutputStream();
                DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
                dataOut.write(array);

                dataOut.flush();
                dataOut.close();


                if (con.getResponseCode() / 100 != 2) {
                    throw new Exception("Error en la respuesta OCSP."
                            + "Codigo de Respuesta:  " + con.getResponseCode());
                }


                InputStream in = (InputStream) con.getContent();
                return new OCSPResp(in);
            } else {
                throw new Exception("Solamente http es soportado para OCSP");
            }
        } catch (IOException e) {
            throw new Exception("No se puede obtener  respuesta OCSP de: " + ocspUrl, e);
        }
    }


    private OCSPReq generarRequestOCSP(X509Certificate in_CertificadoEmisor, BigInteger in_NumeroSerie)
            throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {

            CertificateID id = new CertificateID(CertificateID.HASH_SHA1, in_CertificadoEmisor, in_NumeroSerie);


            OCSPReqGenerator ocspRequestGenerator = new OCSPReqGenerator();
            ocspRequestGenerator.addRequest(id);

            //BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            Vector<DERObjectIdentifier> objectIdentifiers = new Vector<DERObjectIdentifier>();
            Vector<org.bouncycastle.asn1.x509.X509Extension> values = new Vector<org.bouncycastle.asn1.x509.X509Extension>();

            ASN1OctetString asn1 = new DEROctetString(new DEROctetString(new byte[] { 1, 3, 6, 1, 5, 5, 7, 48, 1, 1 }));

            //objectIdentifiers.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            //values.add(new org.bouncycastle.asn1.x509.X509Extension(false, new DEROctetString(nonce.toByteArray())));
            objectIdentifiers.add(OCSPObjectIdentifiers.id_pkix_ocsp);
            values.add(new org.bouncycastle.asn1.x509.X509Extension(false, asn1));
            ocspRequestGenerator.setRequestExtensions(new X509Extensions(objectIdentifiers, values));

            return ocspRequestGenerator.generate();
        } catch (OCSPException e) {
            throw new Exception("No se puede generar OCSP Request con el "
                    + "certificado", e);
        }
    }


    private List<String> GetAuthorityInformationAccessOcspUrl(X509Certificate cert) throws Exception {


        byte[] valorExtensionAIA = cert.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
        if (valorExtensionAIA == null) {
            throw new Exception("El Certificado no contiene AuthorityInformationAccess");
        }

        ASN1InputStream asn1In = new ASN1InputStream(valorExtensionAIA);
        AuthorityInformationAccess authorityInformationAccess;

        try {
            DEROctetString aiaDEROctetString = (DEROctetString) (asn1In.readObject());
            ASN1InputStream asn1InOctets = new ASN1InputStream(aiaDEROctetString.getOctets());
            ASN1Sequence aiaASN1Sequence = (ASN1Sequence) asn1InOctets.readObject();
            authorityInformationAccess = AuthorityInformationAccess.getInstance(aiaASN1Sequence);
        } catch (IOException e) {
            throw new Exception("No se puede leer el certificado para obtener OCSP URLs", e);
        }

        List<String> ocspUrlList = new ArrayList<String>();
        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {

            String oid = accessDescription.getAccessMethod().getId();
            GeneralName gn = accessDescription.getAccessLocation();
            if (gn.getTagNo() == GeneralName.uniformResourceIdentifier &&
                    oid.equals("1.3.6.1.5.5.7.48.1")) {  //ocsp?
                DERIA5String str = DERIA5String.getInstance(gn.getName());
                String accessLocation = str.getString();
                ocspUrlList.add(accessLocation);
            }
        }
        if (ocspUrlList.isEmpty()) {
            throw new Exception("No se puede obtener OCSP urls del certificado");
        }

        return ocspUrlList;
    }
}
