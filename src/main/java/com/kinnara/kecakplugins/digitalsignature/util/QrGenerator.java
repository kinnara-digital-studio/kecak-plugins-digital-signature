package com.kinnara.kecakplugins.digitalsignature.util;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.userview.model.UserviewMenu;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;

public interface QrGenerator {
    /**
     * Generate
     * @param menu
     * @param outputStream
     * @throws IOException
     * @throws WriterException
     */
    default void writeQrCodeMenuToStream(@Nonnull UserviewMenu menu, final OutputStream outputStream) throws IOException, WriterException {
        String content = AppUtil.processHashVariable(menu.getPropertyString("content"), null, null, null);
        int width = Integer.parseInt(menu.getPropertyString("width"));
        int height = Integer.parseInt(menu.getPropertyString("height"));
        writeQrCodeToStream(content, width, height, outputStream);
    }

    /**
     * Generate content as qrcode
     *
     * @param content
     * @param width
     * @param height
     * @param outputStream
     * @throws WriterException
     * @throws IOException
     */
    default void writeQrCodeToStream(@Nonnull String content, int width, int height, @Nonnull final OutputStream outputStream) throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, width, height);
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
    }
}
