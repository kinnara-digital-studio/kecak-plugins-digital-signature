package com.kinnara.kecakplugins.digitalsignature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

import javax.imageio.ImageIO;
import javax.xml.bind.DatatypeConverter;

import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.Element;
import org.joget.apps.form.model.FormBuilderPaletteElement;
import org.joget.apps.form.model.FormData;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;

import net.glxn.qrgen.javase.QRCode;


public class QRElement extends Element implements FormBuilderPaletteElement{

	@Override
	public String getFormBuilderTemplate() {
		return "<label class='label' style='position:absolute;top:10px;left:10px;'>QR Code</label><div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'><span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:50px;align:center;'>QR Code Here</span><div>";
	}

	@Override
	public String getLabel() {
		return getName();
	}

	@Override
	public String getClassName() {
		return getClass().getName();
	}

	@Override
	public String getPropertyOptions() {
		return AppUtil.readPluginResource(getClass().getName(), "/properties/qrCode.json", null, true, "/message/qrCode");
	}

	@Override
	public String getName() {
		return "QR Code";
	}

	@Override
	public String getVersion() {
		return getClass().getPackage().getImplementationVersion();
	}

	@Override
	public String getDescription() {
		return getClass().getPackage().getImplementationTitle();
	}

	@Override
	public String getFormBuilderCategory() {
		return "Kecak";
	}

	@Override
	public int getFormBuilderPosition() {
		return 400;
	}

	@Override
	public String getFormBuilderIcon() {
		return "/plugin/org.joget.apps.form.lib.TextField/images/textField_icon.gif";
	}

	@Override
	public String renderTemplate(FormData formData, Map dataModel) {
		String template = "qrCode.ftl";
		
		String qrString = this.getPropertyString("qrString");
		
		try(ByteArrayOutputStream stream = QRCode
			      .from(qrString)
			      .withSize(250, 250)
			      .stream();
				ByteArrayInputStream bis = new ByteArrayInputStream(stream.toByteArray());){
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ImageIO.write(ImageIO.read(bis), "png", baos);
			
			String data = DatatypeConverter.printBase64Binary(baos.toByteArray());
	        String imageString = "data:image/png;base64," + data;
			dataModel.put("src", imageString);
			
		} catch (IOException e) {
			LogUtil.error(getClassName(),e, e.getMessage());
		}

		String html = FormUtil.generateElementHtml(this, formData, template, dataModel);
		return html;
	}

}
