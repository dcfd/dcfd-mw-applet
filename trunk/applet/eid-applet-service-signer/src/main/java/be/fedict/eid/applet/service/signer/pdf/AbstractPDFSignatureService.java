package be.fedict.eid.applet.service.signer.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import java.io.File;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Document Service implementation of PDF formats.
 *
 * @author Juan Barrancos
 */
abstract public class AbstractPDFSignatureService extends
		be.fedict.eid.applet.service.signer.AbstractPDFSignatureService {

	private static final Log LOG = LogFactory
			.getLog(AbstractPDFSignatureService.class);


	public AbstractPDFSignatureService(DigestAlgo digestAlgo) {
		super(digestAlgo);

	}

        @Override
        abstract protected  String getTimeStampServiceURL();

        @Override
        abstract protected URL getTempPDFDocumentURL();

        @Override
        abstract protected File getTempPDFDocument();


	@Override
	protected final OutputStream getSignedDocumentOutputStream() {
		LOG.debug("get signed document output stream");
		/*
		 * Create each time a new object; we want an empty output stream to
		 * start with.
		 */
		OutputStream signedDocumentOutputStream = new PDFSignedDocumentOutputStream();
		return signedDocumentOutputStream;
	}

	private class PDFSignedDocumentOutputStream extends ByteArrayOutputStream {

		@Override
		public void close() throws IOException {
			LOG.debug("close PDF signed document output stream");
			super.close();
			outputSignedOpenDocument(this.toByteArray());
		}
	}

	private void outputSignedOpenDocument(byte[] signatureData)
			throws IOException {
		LOG.debug("output signed open document");
		OutputStream signedPdfOutputStream = getSignedOpenDocumentOutputStream();
		if (null == signedPdfOutputStream) {
			throw new NullPointerException(
					"signedOpenDocumentOutputStream is null");
		}
                signedPdfOutputStream.write(signatureData, 0, signatureData.length);
                signedPdfOutputStream.close();
	}

	/**
	 * The output stream to which to write the signed PDF file.
	 * 
	 * @return
	 */
	abstract protected OutputStream getSignedOpenDocumentOutputStream();

	public final String getFilesDigestAlgorithm() {
		/*
		 * No local files to digest.
		 */
		return null;
	}

}
