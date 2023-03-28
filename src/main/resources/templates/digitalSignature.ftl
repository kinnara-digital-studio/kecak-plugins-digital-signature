<#if includeMetaData!>
	<label class='label' >Digital Signature</label>
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
	<div id="document-container" style="width:750px;height:600px;overflow-y:scroll;">
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
		<div class="wrapper">
		<canvas id="the-canvas" width="100%" height="500px" style="display:block;cursor:pointer;cursor: hand;"></canvas>
		<canvas id="c"></canvas>
        </div>
        <i id="item-delete-btn" class="item-btn item-btn-danger md-icon md-light material-icons">clear</i>
        <i id="item-confirm-btn" class="item-btn item-btn-success md-icon md-light material-icons">check</i>
		<div class="uk-panel uk-panel-box" id="signature-or-initial">
			<div class="item">
				<img src="" alt="Signature" data-tipe="1" draggable="true">
			</div>
		</div>
				
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
	</div>
	
	<script>
		$(document).ready(function(){
			var url = "${request.contextPath}${pdfFile!?html}";
			
			pdfjsLib.GlobalWorkerOptions.workerSrc = '${request.contextPath}/plugin/${className}/pdf.worker.js';
			
			var pdfDoc = null,
			    pageNum = 1,
			    pageRendering = false,
			    pageNumPending = null,
			    scale = 1,
				canvas = document.getElementById('the-canvas'),
			    fcanvas = document.getElementById('c'),
			    fobject = null,
		        gesture = null,
		        ctx = canvas.getContext('2d');
	        var dataObjects = []
		  	var isDragging = false;
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
					canvas.height = viewport.height;
					canvas.width = viewport.width;
			
					// Render PDF page into canvas context
					var renderContext = {
					  canvasContext: ctx,
					  viewport: viewport
					};
					var renderTask = page.render(renderContext);
			
					// Wait for rendering to finish
					renderTask.promise.then(function() {
						pageRendering = false;
						const signed = JSON.parse(`[]`);
						if (!fobject) {
							fcanvas.width  = canvas.width;
							fcanvas.height = canvas.height;
								
							fobject = new fabric.Canvas(fcanvas, {
								width    : fcanvas.offsetWidth,
								height   : fcanvas.offsetHeight,
								selection: false,
							});
								
							fabric.Image.fromURL('${signatureFile!?html}', function(img){
								fobject.add(img);
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
			.catch(e => {
			    console.log(e);
			});
		});
	
	</script>
</#if>