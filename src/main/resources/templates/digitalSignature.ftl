<#if includeMetaData!>
	<label class='label' >Digital Signature</label>
	<div class="form-cell" ${elementMetaData!}>
	    <label class="label" style="position:absolute;top:10px;left:10px;">
			${element.properties.label} 
			<span class="form-cell-validator">${decoration}</span>
			<#if error??> <span class="form-error-message">${error}</span></#if>
		</label>
		<div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'>
			<span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:70px;align:center;'>PDF</span>
		<div>
	</div>
<#else>
	<script type="text/javascript" src="${request.contextPath}/plugin/${className}/pdf.js"/></script>
	<canvas id="pdf-canvas" width="100%" height="500px"></canvas>
	
	<script>
		$(document).ready(function(){
			var url = "${request.contextPath}${pdfFile!?html}";
			
			pdfjsLib.GlobalWorkerOptions.workerSrc = '${request.contextPath}/plugin/${className}/pdf.worker.js';
			var loadingTask = pdfjsLib.getDocument(url);
		  	loadingTask.promise.then(function(pdf) {
				//
				// Fetch the first page
				//
				pdf.getPage(1).then(function(page) {
					var scale = 1.5;
					var viewport = page.getViewport({ scale: scale, });
					//
					// Prepare canvas using PDF page dimensions
					//
					var canvas = document.getElementById('pdf-canvas');
					var context = canvas.getContext('2d');
					canvas.height = viewport.height;
					canvas.width = viewport.width;
					//
					// Render PDF page into canvas context
					//
					var renderContext = {
					canvasContext: context,
					viewport: viewport,
					};
					page.render(renderContext);
				});
			});
		});
	
	</script>
</#if>