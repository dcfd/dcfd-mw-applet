package be.fedict.eid.dss.document.pdf;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.facets.RevocationDataService;
import be.fedict.eid.applet.service.signer.time.TimeStampService;
import be.fedict.eid.applet.service.signer.time.TimeStampServiceValidator;
import be.fedict.eid.applet.service.spi.IdentityDTO;
import be.fedict.eid.applet.service.spi.SignatureServiceEx;
import be.fedict.eid.dss.spi.DSSDocumentContext;
import be.fedict.eid.dss.spi.DSSDocumentService;
import be.fedict.eid.dss.spi.DocumentVisualization;
import be.fedict.eid.dss.spi.MimeType;
import be.fedict.eid.dss.spi.SignatureInfo;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.LtvVerification.CertificateOption;
import com.itextpdf.text.pdf.security.LtvVerifier;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.VerificationOK;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Document Service implementation of PDF formats.
 * 
 * @author Juan Barrancos
 */
public class PDFDSSDocumentService implements DSSDocumentService {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(PDFDSSDocumentService.class);

	private DSSDocumentContext documentContext;


        @Override
	public void init(DSSDocumentContext context, String contentType)
			throws Exception {

		LOG.debug("init");
		this.documentContext = context;
	}

        @Override
	public void checkIncomingDocument(byte[] document) throws Exception {

		LOG.debug("checkIncomingDocument");
                LOG.debug("content size: " + document.length);
	}

        @Override
	public DocumentVisualization findDocument(byte[] parentDocument,
			String resourceId) throws Exception {

		return null;
	}

        @Override
	public DocumentVisualization visualizeDocument(byte[] document,
			String language, List<MimeType> mimeTypes,
			String documentViewerServlet) throws Exception {

		LOG.debug("visualizeDocument");
		return null;
	}

        @Override
	public SignatureServiceEx getSignatureService(
			InputStream documentInputStream, TimeStampService timeStampService,
			TimeStampServiceValidator timeStampServiceValidator,
			RevocationDataService revocationDataService,
			SignatureFacet signatureFacet, OutputStream documentOutputStream,
			String role, IdentityDTO identity, byte[] photo,
			DigestAlgo signatureDigestAlgo) throws Exception {

		LOG.debug("getSignatureService");
		return new PDFSignatureService(timeStampServiceValidator,
				revocationDataService, signatureFacet, documentInputStream,
				documentOutputStream, timeStampService, role, identity, photo,
				signatureDigestAlgo, this.documentContext);
	}

	@Override
	public List<SignatureInfo> verifySignatures(byte[] document,
			byte[] originalDocument) throws Exception {

		List<SignatureInfo> signatureInfos = new LinkedList<SignatureInfo>();

                Security.addProvider (new BouncyCastleProvider ());

                String firstName = null;
                String role = null;
                String signerName = null;
                String middleName = null;
                SignatureInfo.Gender gender = null;
                byte[] photo = null;

                PdfReader reader = new PdfReader(document);

                AcroFields af = reader.getAcroFields();
                ArrayList<String> names = af.getSignatureNames();
                for (String name : names) {
                    LOG.debug("Signature name: " + name);
                    LOG.debug("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
                    LOG.debug("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
                    PdfPKCS7 pk = af.verifySignature(name, "BC");
                    X509Certificate signingCertificate = (X509Certificate) pk.getSigningCertificate();


                    SignatureInfo signatureInfo = new SignatureInfo(signingCertificate, pk.getSignDate().getTime(),
                                                role, firstName, signerName, middleName, gender, photo);

                    signatureInfos.add(signatureInfo);

                }
		
		return signatureInfos;
	}

}
