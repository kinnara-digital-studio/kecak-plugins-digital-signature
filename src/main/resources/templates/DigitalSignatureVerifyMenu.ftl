<!-- page specific plugin styles -->
<link rel="stylesheet" href="${request.contextPath!}/plugin/${className!}/dropzone/dropzone.min.css" />
<script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/build/pdf.js"/></script>
<script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/fabric/dist/fabric.min.js"/></script>
<style>
#pdfCanvas {
  display:none;
  border: 1px solid #ccc;
}
</style>
<h1>${label!} Menu</h1>

<div class="row">
	<div class="col-xs-12">
        <div class="alert alert-info">
            <i class="ace-icon fa fa-hand-o-right"></i>

            Please note that demo server is not configured to save uploaded files, therefore you may get an error message.
            <button class="close" data-dismiss="alert">
                <i class="ace-icon fa fa-times"></i>
            </button>
        </div>

        <div>
            <form  class="dropzone well" id="dropzone">
                <div class="fallback">
                    <input name="file" type="file" multiple="" />
                </div>
            </form>

        </div>

        <canvas id="pdfCanvas"></canvas>

        <div id="preview-template" class="hide">
            <div class="dz-preview dz-file-preview">
                <div class="dz-image">
                    <img data-dz-thumbnail="" />
                </div>

                <div class="dz-details">
                    <div class="dz-size">
                        <span data-dz-size=""></span>
                    </div>

                    <div class="dz-filename">
                        <span data-dz-name=""></span>
                    </div>
                </div>

                <div class="dz-progress">
                    <span class="dz-upload" data-dz-uploadprogress=""></span>
                </div>

                <div class="dz-error-message">
                    <span data-dz-errormessage=""></span>
                </div>

                <div class="dz-success-mark">
                    <span class="fa-stack fa-lg bigger-150">
                        <i class="fa fa-circle fa-stack-2x white"></i>

                        <i class="fa fa-check fa-stack-1x fa-inverse green"></i>
                    </span>
                </div>

                <div class="dz-error-mark">
                    <span class="fa-stack fa-lg bigger-150">
                        <i class="fa fa-circle fa-stack-2x white"></i>

                        <i class="fa fa-remove fa-stack-1x fa-inverse red"></i>
                    </span>
                </div>
            </div>
        </div>

    </div>
</div>



<!-- page specific plugin scripts -->
<script type="text/javascript" src="${request.contextPath}/plugin/${className}/dropzone/dropzone.min.js"></script>
<script type="text/javascript">
Dropzone.autoDiscover = false;
var myDropzone = new Dropzone("#dropzone", {

  url: "${request.contextPath!}/web/json/plugin/com.kinnara.kecakplugins.digitalsignature.webapi.VerifyApi/service", // Replace with your upload URL
  addRemoveLinks : true,
  //autoProcessQueue: false, // Disable auto processing on drop

  init: function () {
    this.on("drop", function () {

      //this.removeAllFiles(); // Clear the existing files from the queue
      this.processQueue(); // Process the dropped files
    });

    this.on("addedfile", function (file) {
      console.log("File added: " + file.name);

      if (file.type === 'application/pdf') {
            var reader = new FileReader();

            reader.onload = function(e) {
              var pdfData = new Uint8Array(e.target.result);

              // Render the PDF on the canvas
              renderPDF(pdfData);
            };

            reader.readAsArrayBuffer(file);
          }
    });

    this.on("removedfile", function (file) {
      document.getElementById('pdfCanvas').style.display="none";
      console.log("File removed: " + file.name);
    });

    this.on("success", function (file, response) {
      console.log("File uploaded successfully!");
      document.getElementById('pdfCanvas').style.display="block";
      //console.log(response.Data); // Log the server's response
      var signData = response.Data;

      for (var i = 0; i < signData.length; i++) {
        var obj = signData[i];
        console.log("Signature Name :" + obj.signatureName)

        var innerArray = obj.rootData;
        for (var j = 0; j < innerArray.length; j++) {
          var innerObj = innerArray[j];
          for (var key in innerObj) {
            console.log(key + ": " + innerObj[key]);
          }
        }
        console.log("----------------------");
        }
    });

    this.on("error", function (file, errorMessage) {
      console.log("Error uploading file: " + errorMessage);
    });
  }
})

function renderPDF(pdfData) {
pdfjsLib.GlobalWorkerOptions.workerSrc = "${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/build/pdf.worker.js";
  pdfjsLib.getDocument(pdfData).promise.then(function(pdf) {
    // Get the first page of the PDF
    pdf.getPage(1).then(function(page) {
      var canvas = document.getElementById('pdfCanvas');
      var context = canvas.getContext('2d');
      var viewport = page.getViewport({ scale: 1 });

      // Set the canvas size to match the PDF page
      canvas.width = viewport.width;
      canvas.height = viewport.height;

      // Render the PDF page on the canvas
      var renderContext = {
        canvasContext: context,
        viewport: viewport,
      };
      page.render(renderContext);
    });
  });
}
</script>
