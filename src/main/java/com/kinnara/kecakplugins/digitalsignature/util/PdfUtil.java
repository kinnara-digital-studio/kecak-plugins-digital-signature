package com.kinnara.kecakplugins.digitalsignature.util;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.AffineTransform;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import net.glxn.qrgen.javase.QRCode;
import org.joget.commons.util.LogUtil;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.util.ResourceUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Nonnull;
import javax.imageio.ImageIO;
import java.io.*;
import java.net.URL;
import java.util.Collections;
import java.util.Map;

public interface PdfUtil {
    String PATH_CERTIFICATE = "wflow/app_certificate/";

    String TEMP_FILE_EXTENSION = ".tmp";

    default void stampPdf(File pdfFile, File stampFile, int page, float left, float top, float xScale, float yScale, double rotate) throws IOException {
        final byte[] bytes = new byte[(int) stampFile.length()];
        try (FileInputStream fis = new FileInputStream(stampFile)) {
            fis.read(bytes);
        }

        stampPdf(pdfFile, bytes, page, left, top, xScale, yScale, rotate);
    }

    default void stampPdf(File pdfFile, MultipartFile stampFile, int page, float left, float top, float xScale, float yScale, double rotate) throws IOException {
        final byte[] bytes = stampFile.getBytes();
        stampPdf(pdfFile, bytes, page, left, top, xScale, yScale, rotate);
    }

    default void stampPdf(File pdfFile, byte[] stampFile, int page, float left, float top, float xScale, float yScale, double rotate) throws IOException {
        final String tempFilePath = pdfFile.getPath() + TEMP_FILE_EXTENSION;
        final File tempPdfFile = new File(tempFilePath);

        try (PdfReader reader = new PdfReader(pdfFile);
             PdfWriter writer = new PdfWriter(tempFilePath);
             PdfDocument tempDocument = new PdfDocument(reader, writer)) {

            LogUtil.debug(getClass().getName(), "Creating temp file [" + tempPdfFile.getPath() + "]");
        }

        try (PdfReader reader = new PdfReader(tempPdfFile);
             PdfWriter writer = new PdfWriter(pdfFile);
             PdfDocument pdf = new PdfDocument(reader, writer, new StampingProperties().useAppendMode())) {

            final PdfPage pdfPage = pdf.getPage(page);
            final float pageHeight = pdfPage.getPageSize().getHeight();

            final ImageData stampImageData = ImageDataFactory.createPng(stampFile);
            final float stampHeight = stampImageData.getHeight();

            final PdfCanvas canvas = new PdfCanvas(pdfPage);
            final float bottom = pageHeight - top - (stampHeight * yScale);

            final AffineTransform t = AffineTransform.getTranslateInstance(left, bottom);
            t.scale(stampImageData.getWidth() * xScale, stampImageData.getHeight() * yScale);

            final float[] matrix = new float[6];
            t.getMatrix(matrix);

            canvas.addImageWithTransformationMatrix(stampImageData, matrix[0], matrix[1], matrix[2], matrix[3], matrix[4], matrix[5], false);

            if (tempPdfFile.delete()) {
                LogUtil.debug(getClass().getName(), "Temp file [" + tempPdfFile.getPath() + "] has been deleted");
            } else {
                LogUtil.warn(getClass().getName(), "Error deleting temp file [" + tempPdfFile.getPath() + "]");
            }
        }
    }

    default File getSignature() throws FileNotFoundException {
        final String username = WorkflowUtil.getCurrentUsername();
        return getSignature(username);
    }

    default File getSignature(String username) throws FileNotFoundException {
        final URL url = ResourceUtils.getURL(PATH_CERTIFICATE + "/" + username + "/signature.png");
        final File signatureFile = new File(url.getPath());
        return signatureFile;
    }

    default byte[] getQrCode(String qrString) throws IOException {
        try (ByteArrayOutputStream stream = QRCode
                .from(qrString)
                .withSize(250, 250)
                .stream();
             ByteArrayInputStream bis = new ByteArrayInputStream(stream.toByteArray());) {

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(ImageIO.read(bis), "png", baos);

            return baos.toByteArray();
        }
    }

    /**
     *
     * @param content       Input : QR content
     * @param outputStream  Output : write to output stream
     * @throws WriterException
     * @throws IOException
     */
    default void writeQrCodeToStream(@Nonnull String content, @Nonnull final OutputStream outputStream) throws WriterException, IOException {
        final int width = 100;
        final int height = 100;
        final QRCodeWriter qrCodeWriter = new QRCodeWriter();
        final Map<EncodeHintType, Object> hintMap = Collections.singletonMap(EncodeHintType.MARGIN, 0);
        final BitMatrix bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, width, height, hintMap);
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
    }
}
