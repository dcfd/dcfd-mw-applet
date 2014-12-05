package be.fedict.eid.applet.service.signer;

import com.itextpdf.text.DocumentException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.SignatureService;
import com.itextpdf.text.Font;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;


import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.LtvTimestamp;
import com.itextpdf.text.pdf.security.LtvVerification;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import com.itextpdf.text.pdf.security.TSAInfoBouncyCastle;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import javax.servlet.http.HttpSession;
import org.apache.commons.compress.utils.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * SignatureService implementation of PDF formats.
 *
 * @author Juan Barrancos
 */

public abstract class AbstractPDFSignatureService implements SignatureService {

    static final Log LOG = LogFactory.getLog(AbstractPDFSignatureService.class);
    private static final String SIGNATURE_ID_ATTRIBUTE = "signature-id";
    private static final String SGN_ATTRIBUTE = "sgn";
    private static final String HASH_ATTRIBUTE = "hash";
    private static final String CAL_ATTRIBUTE = "cal";
    private static final String SAP_ATTRIBUTE = "sap";
    private static final String BAOS_ATTRIBUTE = "baos";
    private static final String OCSP_ATTRIBUTE = "ocsp";
    private static final String CRLS_ATTRIBUTE = "crls";

    private final List<SignatureFacet> signatureFacets;
    private String signatureId;
    private final DigestAlgo digestAlgo;

    int estimatedSize = 8192 + (4192 *10);

    /**
     * Main constructor.
     */
    public AbstractPDFSignatureService(DigestAlgo digestAlgo) {
        this.signatureFacets = new LinkedList<SignatureFacet>();
        this.signatureId = null;
        this.digestAlgo = digestAlgo;
    }

    /**
     * Sets the signature Id attribute value used to create the PDF signature. A
     * <code>null</code> value will trigger an automatically generated signature
     * Id.
     *
     * @param signatureId
     */
    protected void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }


    /**
     * Adds a signature facet to this PDF signature service.
     *
     * @param signatureFacet
     */
    protected void addSignatureFacet(SignatureFacet signatureFacet) {
        this.signatureFacets.add(signatureFacet);
    }

    /**
     * Gives back the signature digest algorithm. Allowed values are SHA-1,
     * SHA-256, SHA-384, SHA-512, RIPEND160. The default algorithm is SHA-1.
     * Override this method to select another signature digest algorithm.
     *
     * @return
     */
    protected DigestAlgo getSignatureDigestAlgorithm() {

        return null != this.digestAlgo ? this.digestAlgo : DigestAlgo.SHA1;
    }

    abstract protected  String getTimeStampServiceURL();

    abstract protected URL getTempPDFDocumentURL();



    abstract protected File getTempPDFDocument();

    /**
     * Gives back the human-readable description of what the citizen will be
     * signing. The default value is "PDF Document". Override this method to
     * provide the citizen with another description.
     *
     * @return
     */
    protected String getSignatureDescription() {
        return "PDF Document";
    }

    /**
     * Gives back a temporary data storage component. This component is used for
     * temporary storage of the PDF signature documents.
     *
     * @return
     */
    protected abstract TemporaryDataStorage getTemporaryDataStorage();

    /**
     * Gives back the output stream to which to write the signed PDF document.
     *
     * @return
     */
    protected abstract OutputStream getSignedDocumentOutputStream();

    public boolean hasValidSignature() throws IOException, GeneralSecurityException{

        Security.addProvider (new BouncyCastleProvider ());
        boolean result = false;
        PdfReader reader = new PdfReader(getTempPDFDocumentURL());

        AcroFields af = reader.getAcroFields();
        ArrayList<String> names = af.getSignatureNames();
        for (String name : names) {
            LOG.debug("Signature name: " + name);
            LOG.debug("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            LOG.debug("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
            PdfPKCS7 pk = af.verifySignature(name, "BC");
            LOG.debug("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));
            result = pk.verify();
            LOG.debug("Revision modified: " + !result);
        }

        return result;
        
    }

    public DigestInfo preSign(List<DigestInfo> digestInfos,
            List<X509Certificate> signingCertificateChain)
            throws NoSuchAlgorithmException {
        LOG.debug("preSign");
        DigestAlgo localDigestAlgo = getSignatureDigestAlgorithm();

        LOG.debug("preSign: " + localDigestAlgo.getAlgoId());

        byte[] digestValue;
        try {
            digestValue = getPDFSignatureDigestValue(localDigestAlgo, digestInfos,
                    signingCertificateChain);
        } catch (Exception e) {
            throw new RuntimeException(
                    "PDF signature error: " + e.getMessage(), e);
        }

        String description = getSignatureDescription();
        return new DigestInfo(digestValue, localDigestAlgo.getAlgoId(), description);
    }

    public void postSign(byte[] signatureValue,
            List<X509Certificate> signingCertificateChain) {
        try {
            LOG.debug("postSign");
            /*
             * Retrieve the intermediate  signature document from the temporary
             * data storage.
             */
            TemporaryDataStorage temporaryDataStorage = getTemporaryDataStorage();
            InputStream documentInputStream = temporaryDataStorage.getTempInputStream();            
            String signatureId = (String) temporaryDataStorage.getAttribute(SIGNATURE_ID_ATTRIBUTE);
            LOG.debug("signature Id: " + signatureId);
            
            HttpSession httpSession = HttpSessionTemporaryDataStorage.getHttpSession();

            PdfPKCS7 sgn = (PdfPKCS7) httpSession.getAttribute(SGN_ATTRIBUTE);
            byte[] hash = (byte[]) httpSession.getAttribute(HASH_ATTRIBUTE);
            Calendar cal = (Calendar) httpSession.getAttribute(CAL_ATTRIBUTE);
            PdfSignatureAppearance sap = (PdfSignatureAppearance) httpSession.getAttribute(SAP_ATTRIBUTE);
            ByteArrayOutputStream baos = (ByteArrayOutputStream) httpSession.getAttribute(BAOS_ATTRIBUTE);

            byte[] ocsp = (byte[]) httpSession.getAttribute(OCSP_ATTRIBUTE);
            List<byte[]> crls = (List<byte[]>) httpSession.getAttribute(CRLS_ATTRIBUTE);

            LOG.debug("Consuming TSA: " + getTimeStampServiceURL());
            TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle(getTimeStampServiceURL(), null, null, TSAClientBouncyCastle.DEFAULTTOKENSIZE, digestAlgo.getAlgoId() );
            TSAInfoBouncyCastle tsaInfo = new TSAInfoBouncyCastle() {
                    public void inspectTimeStampTokenInfo(TimeStampTokenInfo info) {
                        System.out.println();
                        LOG.debug("TimeStampTokenInfo: " + info.getGenTime());
                    } };
            tsaClient.setTSAInfo(tsaInfo);
            
            sgn.setExternalDigest(signatureValue, null, "RSA");
            byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsaClient, ocsp, crls, CryptoStandard.CMS);
            LOG.debug("encodedSig length: " + encodedSig.length);
            if(estimatedSize < encodedSig.length) {
                throw new IllegalArgumentException("Not enough space for PDF Signature");
            }
            byte[] paddedSig = new byte[estimatedSize];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            try {
                sap.close(dic2);
            } catch (DocumentException e) {
                LOG.error("ERROR: "+e.getMessage());
            }

            X509Certificate  signerCertificate = sgn.getSigningCertificate();

            LOG.debug("signerCertificate x509 cert: " + signerCertificate.getSubjectX500Principal());

            /*
             * Allow signature facets to inject their own stuff.
             */
            for (SignatureFacet signatureFacet : this.signatureFacets) {
                    signatureFacet.postSign(null, signingCertificateChain);
            }

            byte[] pdf = baos.toByteArray();

            OutputStream signedDocumentOutputStream = getSignedDocumentOutputStream();
            if (null == signedDocumentOutputStream) {
                throw new IllegalArgumentException("signed document output stream is null");
            }
            signedDocumentOutputStream.write(pdf, 0, pdf.length);
            signedDocumentOutputStream.flush();
            signedDocumentOutputStream.close();

        } catch (IOException ex) {
            Logger.getLogger(AbstractPDFSignatureService.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }


    private byte[] buildOCSPResponse(byte[] BasicOCSPResponse) throws IOException {
            DEROctetString doctet = new DEROctetString(BasicOCSPResponse);
            ASN1EncodableVector v2 = new ASN1EncodableVector();
            v2.add(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
            v2.add(doctet);
            DEREnumerated den = new DEREnumerated(0);
            ASN1EncodableVector v3 = new ASN1EncodableVector();
            v3.add(den);
            v3.add(new DERTaggedObject(true, 0, new DERSequence(v2)));
            DERSequence seq = new DERSequence(v3);
            return seq.getEncoded();
     }

    @SuppressWarnings("unchecked")
    private byte[] getPDFSignatureDigestValue(DigestAlgo digestAlgo,
            List<DigestInfo> digestInfos,
            List<X509Certificate> signingCertificateChain) 
            throws IOException, DocumentException, InvalidKeyException,
            NoSuchProviderException, NoSuchAlgorithmException, GeneralSecurityException
           {


        String localSignatureId;
        if (null == this.signatureId) {
            localSignatureId = "pdfsig-" + UUID.randomUUID().toString();
        } else {
            localSignatureId = this.signatureId;
        }

        java.security.cert.Certificate[] resultChain = new java.security.cert.Certificate[signingCertificateChain.size()];
        signingCertificateChain.toArray(resultChain);
        List<byte[]> crls = new ArrayList<byte[]>();
        CrlClient crlClient = new CrlClientOnline();
        OcspClientBouncyCastle client = new OcspClientBouncyCastle();

        byte[] ocsp = null;
        for (int k = 0; k < resultChain.length; ++k) {
            if(ocsp == null && k < resultChain.length - 1){
                ocsp = client.getEncoded((X509Certificate)resultChain[k], (X509Certificate)resultChain[k + 1], null);
                if (ocsp != null) {
                    continue;
                }
            }
            Collection<byte[]> encods = crlClient.getEncoded((X509Certificate)resultChain[k], null);
            if(encods.isEmpty()) continue;
            Object[] tmp =  encods.toArray();
            byte[] cim = (byte[])tmp[0];
            if (cim != null) {
                boolean dup = false;
                for (byte[] b : crls) {
                    if (Arrays.equals(b, cim)) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    crls.add(cim);
                }
            }

        }


        PdfReader reader = new PdfReader(getTempPDFDocumentURL());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0', null, true);

        PdfSignatureAppearance sap = stamper.getSignatureAppearance();
        sap = stamper.getSignatureAppearance();

        //int pageNumber = reader.getNumberOfPages();
        int pageNumber = 1;
        Rectangle pageSize = reader.getPageSize(pageNumber);

        float width = 120;
        float height = 40;

        AcroFields af = reader.getAcroFields();
        ArrayList<String> names = af.getSignatureNames();
        int numberOfSignatures = names.size();

        int offset = 30;
        if(numberOfSignatures > 0) {
            offset = 5;
        }

        int multiplier;
        if((numberOfSignatures * width) >  pageSize.getWidth()) {
            numberOfSignatures = 0;
        }
        multiplier = numberOfSignatures+1;

        int verticalPosition = (int)(pageSize.getBottom() + 10);
        int signatureEndV = (int) (verticalPosition + height);
        int signatureEndX = (int) (width * multiplier);
        Rectangle position = new Rectangle(offset + (width * numberOfSignatures), verticalPosition, signatureEndX, signatureEndV);


        sap.setVisibleSignature(position, pageNumber, localSignatureId);
        
        sap.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
        sap.setCertificate(signingCertificateChain.get(0));

        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        dic.setReason(sap.getReason());
        dic.setLocation(sap.getLocation());
        dic.setContact(sap.getContact());
        dic.setDate(new PdfDate(sap.getSignDate()));
        sap.setCryptoDictionary(dic);
        HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(estimatedSize * 2 + 2)); 
        sap.preClose(exc);
        
        ExternalDigest externalDigest = new ExternalDigest() {

            public MessageDigest getMessageDigest(String hashAlgorithm)
                    throws GeneralSecurityException {
                return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
            }
        };

        LOG.debug("digestAlgo.getPlainAlgo:"+ digestAlgo.getPlainAlgo());

        PdfPKCS7 sgn = new PdfPKCS7(null, resultChain, digestAlgo.getPlainAlgo(), null, externalDigest, false);
        sgn = new PdfPKCS7(null, resultChain, digestAlgo.getAlgoId(), null, externalDigest, false);
        InputStream data = sap.getRangeStream();
        byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest(digestAlgo.getAlgoId()));
        Calendar cal = Calendar.getInstance();
        
        byte[] digestValue = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp, crls, CryptoStandard.CMS);

        digestValue = DigestAlgorithms.digest(new ByteArrayInputStream(digestValue), externalDigest.getMessageDigest(digestAlgo.getAlgoId()));

        LOG.debug("digestValue length: "+ digestValue.length);


        TemporaryDataStorage temporaryDataStorage = getTemporaryDataStorage();
        OutputStream tempDocumentOutputStream = temporaryDataStorage.getTempOutputStream();
        
        IOUtils.copy(data, tempDocumentOutputStream);
        
        temporaryDataStorage.setAttribute(SIGNATURE_ID_ATTRIBUTE, localSignatureId);
        tempDocumentOutputStream.close();

        HttpSession httpSession = HttpSessionTemporaryDataStorage.getHttpSession();
        httpSession.setAttribute(SGN_ATTRIBUTE, sgn);
        httpSession.setAttribute(HASH_ATTRIBUTE, hash);
        httpSession.setAttribute(CAL_ATTRIBUTE, cal);
        httpSession.setAttribute(SAP_ATTRIBUTE, sap);
        httpSession.setAttribute(BAOS_ATTRIBUTE, baos);
        httpSession.setAttribute(OCSP_ATTRIBUTE, ocsp);
        httpSession.setAttribute(CRLS_ATTRIBUTE, crls);

        return digestValue;
    }
}
