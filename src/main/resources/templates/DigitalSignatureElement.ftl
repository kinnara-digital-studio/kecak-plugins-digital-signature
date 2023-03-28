
<#if includeMetaData!>
	<label class='label' >Digital Signature</label>
	<div class="form-cell" ${elementMetaData!}>
	    <label class="label" style="position:absolute;top:10px;left:10px;">
			${element.properties.label!}
			<span class="form-cell-validator">${decoration!}</span>
			<#if error??> <span class="form-error-message">${error}</span></#if>
		</label>
		<div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'>
			<span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:70px;align:center;'>PDF</span>
		<div>
	</div>
<#else>
    <#assign uniqueKey = element.properties.elementUniqueKey >
    <h1>Digital Signatures</h1>

	<script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/build/pdf.js"/></script>

	<a href="${pdfPath}">Link to PDF</a>

	<a href="${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/web/viewer.html">View</a>

    <div id="pdf-viewer-${uniqueKey}">
        <canvas id="stampCanvas"></canvas>
    </div>

	<script type="text/javascript">
        $(document).ready(function(){
            pdfjsLib.GlobalWorkerOptions.workerSrc = "${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/build/pdf.worker.js";

            let url = "${pdfPath}";

            pdfjsLib.getDocument(url).promise.then(function(pdf) {
                let viewer = document.getElementById('pdf-viewer-${uniqueKey}');

                for(let page = 1; page <= pdf.numPages; page++) {
                  let canvas = document.createElement("canvas");
                  canvas.className = 'pdf-page-canvas';
                  viewer.appendChild(canvas);
                  renderPage(pdf, page, canvas);
                }
            });

            function renderPage(pdf, pageNumber, canvas) {
                pdf.getPage(pageNumber).then(function(page) {
                    let scale = 1.5;
                    let viewport = page.getViewport({scale: scale});

                    // Prepare canvas using PDF page dimensions
                    let context = canvas.getContext('2d');
                    canvas.height = viewport.height;
                    canvas.width = viewport.width;

                    // Render PDF page into canvas context
                    let renderContext = {
                      canvasContext: context,
                      viewport: viewport
                    };

                    let renderTask = page.render(renderContext);
                });


                const stampCanvas = document.getElementById('stampCanvas');
                const stampContext = stampCanvas.getContext('2d');

                stampContext.font = 'bold 20px Arial';
                stampContext.fillStyle = 'red';
                stampContext.fillText('STAMP', 10, 30);

            }
        });

    </script>
</#if>