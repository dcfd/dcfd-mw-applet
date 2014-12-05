package be.fedict.eid.dss.document.pdf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.io.IOUtils;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.HttpSessionTemporaryDataStorage;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.signer.facets.RevocationDataService;
import be.fedict.eid.applet.service.signer.pdf.AbstractPDFSignatureService;
import be.fedict.eid.applet.service.signer.time.TimeStampService;
import be.fedict.eid.applet.service.signer.time.TimeStampServiceValidator;
import be.fedict.eid.applet.service.spi.AddressDTO;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityDTO;
import be.fedict.eid.applet.service.spi.SignatureServiceEx;
import be.fedict.eid.dss.spi.DSSDocumentContext;
import be.fedict.eid.dss.spi.utils.CloseActionOutputStream;

/**
 * Document Service implementation of PDF formats.
 *
 * @author Juan Barrancos
 */
public class PDFSignatureService extends AbstractPDFSignatureService implements
		SignatureServiceEx {

	private final TemporaryDataStorage temporaryDataStorage;

	private final OutputStream documentOutputStream;

	private final File tmpFile;

        private final TimeStampService timeStampService;

        @Override
        protected String getTimeStampServiceURL(){
            return timeStampService.getTimeStampServiceURL();
        }

	public PDFSignatureService(
			TimeStampServiceValidator timeStampServiceValidator,
			RevocationDataService revocationDataService,
			SignatureFacet signatureFacet, InputStream documentInputStream,
			OutputStream documentOutputStream,
			TimeStampService timeStampService, String role,
			IdentityDTO identity, byte[] photo, DigestAlgo digestAlgo,
			DSSDocumentContext documentContext) throws Exception {

		super(DigestAlgo.SHA1);

		this.temporaryDataStorage = new HttpSessionTemporaryDataStorage();
		this.documentOutputStream = documentOutputStream;
		this.tmpFile = File.createTempFile("eid-dss-", ".pdf");
                this.timeStampService = timeStampService;

		documentContext.deleteWhenSessionDestroyed(this.tmpFile);
		FileOutputStream fileOutputStream;
		fileOutputStream = new FileOutputStream(this.tmpFile);
		IOUtils.copy(documentInputStream, fileOutputStream);
                addSignatureFacet(signatureFacet);

	}

        @Override
	protected URL getTempPDFDocumentURL() {
		try {
			return this.tmpFile.toURI().toURL();
		} catch (MalformedURLException e) {
			throw new RuntimeException("URL error: " + e.getMessage(), e);
		}
	}

        @Override
        protected File getTempPDFDocument(){
            return tmpFile;
        }


	@Override
	protected OutputStream getSignedOpenDocumentOutputStream() {
		return new CloseActionOutputStream(this.documentOutputStream,
				new CloseAction());
	}

	private class CloseAction implements Runnable {
		public void run() {
			PDFSignatureService.this.tmpFile.delete();
		}
	}

	@Override
	protected TemporaryDataStorage getTemporaryDataStorage() {
		return this.temporaryDataStorage;
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain,
			IdentityDTO identity, AddressDTO address, byte[] photo)
			throws NoSuchAlgorithmException {
		return super.preSign(digestInfos, signingCertificateChain);
	}
        
    @Override
        public void setHttpSessionObject(Object sessionObject){

        }
}
