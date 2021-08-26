<#if includeMetaData!>
	<label class='label' >QR Code</label>
	<div class="form-cell" ${elementMetaData!}>
	    <label class="label" style="position:absolute;top:10px;left:10px;">
			${element.properties.label} 
			<span class="form-cell-validator">${decoration}</span>
			<#if error??> <span class="form-error-message">${error}</span></#if>
		</label>
		<div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'>
			<span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:50px;align:center;'>QR Code Here</span>
		<div>
	</div>
<#else>
	<div class="form-cell" ${elementMetaData!}>
		<label class="label">${element.properties.label} <span class="form-cell-validator">${decoration}</span><#if error??> <span class="form-error-message">${error}</span></#if></label>
		<div class="form-cell-value">
			<img src="${src!?html}"/>
		</div>
	</div>
</#if>