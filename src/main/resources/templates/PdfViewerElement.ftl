<#if includeMetaData!>
	<div class="form-cell" ${elementMetaData!}>
	    <label class="label" style="position:absolute;top:10px;left:10px;">
			${element.properties.label!}
			<span class="form-cell-validator">${decoration!}</span>
			<#if error??> <span class="form-error-message">${error!}</span></#if>
		</label>
		<div style='border: 5px solid grey;height:100px;background-color:#EFF1F2;color:#C4C7CB;align:center;'>
			<span style='position:absolute;top:10px;left:270px;font-weight:bold;font-size:70px;align:center;'>PDF</span>
		<div>
	</div>
<#else>
    <#assign uniqueKey = element.properties.elementUniqueKey >

	<script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/build/pdf.js"/></script>
	<script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/fabric/dist/fabric.min.js"/></script>
	<style>
		.md-btn {
		    background: #2916c3;
		    border: none;
		    border-radius: 4px;
		    min-height: 31px;
		    min-width: 70px;
		    padding: 4px 16px;
		    text-align: center;
		    text-shadow: none;
		    text-transform: uppercase;
		    -webkit-transition: all 280ms cubic-bezier(.4, 0, .2, 1);
		    transition: all 280ms cubic-bezier(.4, 0, .2, 1);
		    color: #fffff;
		    box-sizing: border-box;
		    cursor: pointer;
		    -webkit-appearance: none;
		    display: inline-block;
		    vertical-align: middle;
		    font: 500 14px/31px Roboto, sans-serif!important;
		}
		.wrapper {
		    position: relative;
		    height: 500px;
		}
		
		.wrapper canvas {
		    position: absolute;
		    top: 0;
		    left: 0;
		}
	</style>
	<div class="form-cell">
        <div style="text-align:center;background-color: #5480fb;color: #e5e5ef;">
            <span class="md-btn md-btn-secondary prev" style="cursor:pointer;">
                <i class="fa fa-angle-left"></i>
                Prev
            </span>
            ||
            <span class="md-btn md-btn-secondary next" style="cursor:pointer;">
                <i class="fa fa-angle-right"></i>
                Next
            </span>
            &nbsp; &nbsp;
            <span>Page: <span class="page_num"></span> / <span class="page_count"></span></span>
        </div>
        <div id="document-container-${uniqueKey}" style="width:750px;height:600px;overflow-y:scroll;background: gray">
            <div class="wrapper">
                <canvas id="pdf-canvas-${uniqueKey}" width="100%" height="500px" style="display:block;cursor:pointer;cursor: hand;"></canvas>
                <canvas id="stamp-canvas-${uniqueKey}"></canvas>
            </div>
            <div class="uk-panel uk-panel-box" id="signature-or-initial">
                <div class="item">
                    <img src="" alt="Signature" data-tipe="1" >
                </div>
            </div>

            <!--
            <div style="text-align:center;background-color: #5480fb;color: #e5e5ef;">
                <span class="md-btn md-btn-secondary prev" style="cursor:pointer;">
                    <i class="fa fa-angle-left"></i>
                    Previous
                </span>
                ||
                <span class="md-btn md-btn-secondary next" style="cursor:pointer;">
                    <i class="fa fa-angle-right"></i>
                    Next
                </span>
                &nbsp; &nbsp;
                <span>Page: <span class="page_num"></span> / <span class="page_count"></span></span>
            </div>
            -->
        </div>
        <input id="${elementParamName!}_${uniqueKey!}" name="${elementParamName!}" type="hidden" value="1;0;0;1;1">
	</div>
	<script>
		$(document).ready(function(){
			var url = "${request.contextPath}${pdfFile!?html}";
			
            pdfjsLib.GlobalWorkerOptions.workerSrc = "${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/build/pdf.worker.js";

			var pdfDoc = null,
			    pageNum = 1,
			    pageRendering = false,
			    pageNumPending = null,
			    scale = 1,
				pdfCanvas = document.getElementById('pdf-canvas-${uniqueKey}'),
			    stampCanvas = document.getElementById('stamp-canvas-${uniqueKey}'),
			    fobject = null,
		        gesture = null,
		        ctx = pdfCanvas.getContext('2d');
	        var dataObjects = []
		  	var Pages = 0;
    		var outside = 0;
  			var x;
  			var y;
 	 		var add = false;
  			var pageSignature = 1;
  			
			function renderPage(num) {
				pageRendering = true;
				// Using promise to fetch the page
				pdfDoc.getPage(num).then(function(page) {
					var viewport = page.getViewport({scale: scale});
					pdfCanvas.height = viewport.height;
					pdfCanvas.width = viewport.width;
			
					// Render PDF page into canvas context
					var renderContext = {
					  canvasContext: ctx,
					  viewport: viewport
					};
					var renderTask = page.render(renderContext);
			
					// Wait for rendering to finish
					renderTask.promise.then(function() {
						pageRendering = false;
						if ('${stampFile!}' && !fobject) {
							stampCanvas.width  = pdfCanvas.width;
							stampCanvas.height = pdfCanvas.height;

							fobject = new fabric.Canvas(stampCanvas, {
								width    : stampCanvas.offsetWidth,
								height   : stampCanvas.offsetHeight,
								selection: false
							});
								
							fabric.Image.fromURL('${request.contextPath}${stampFile!?html}', function(img){
								fobject.add(img);
								fobject.on('object:moving', onStampChange, false);
								fobject.on('object:scaling', onStampChange, false);
								img.controls.mtr = new fabric.Control({ visible: false });
							});
						}
							
						if (pageNumPending !== null) {
							// New page rendering is pending
							renderPage(pageNumPending);
							pageNumPending = null;
						}
					});
				});
			
				 // Update page counters
				 $('.page_num').html(num);

				 onPageChange(num);
			}

			function onStampChange(event) {
                let top = event.transform.target.top;
                let left = event.transform.target.left;
                let scaleY = event.transform.target.scaleY;
                let scaleX = event.transform.target.scaleX;
                let height = scaleY * event.transform.target.height;
                let width = scaleX * event.transform.target.width;

                let value = [pageNum, top, left, scaleY, scaleX].join(';');
                $('#${elementParamName!}_${uniqueKey!}').val(value);
            }

            function onPageChange(page) {
                let oldValue = $('#${elementParamName!}_${uniqueKey!}').val();

                let split = oldValue.split(';');
                let top = split[1]
                let left = split[2];
                let scaleY = split[3];
                let scaleX = split[4];

                let newValue = [page, top, left, scaleY, scaleX].join(';');
                $('#${elementParamName!}_${uniqueKey!}').val(newValue);
            }
			
			function queueRenderPage(num) {
			  if (pageRendering) {
			    pageNumPending = num;
			  } else {
			    renderPage(num);
			  }
			}
			
			function onPrevPage() {
				if (pageNum <= 1) {
					return;
				}
				pageNum--;
				queueRenderPage(pageNum);
			}
			$('.prev').on('click', onPrevPage);

			function onNextPage() {
				if (pageNum >= pdfDoc.numPages) {
					return;
				}
				pageNum++;
				queueRenderPage(pageNum);
			}
			$('.next').on('click', onNextPage);
			
			pdfjsLib.getDocument(url)
			.promise
			.then(pdfDoc_ => {
			  		pdfDoc = pdfDoc_;
			  		$('.page_count').html(pdfDoc.numPages);
			
					// Initial/first page rendering
					renderPage(pageNum);
            })
			.catch(console.error);
		});
	
	</script>
</#if>