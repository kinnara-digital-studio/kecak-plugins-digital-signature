<div class="body-content">
    <fieldset id="form-canvas">
        <form  class="form-container " id="verify">
            <div class="form-section">
                <div class="form-section-title"><span>${label!}</span></div>
                <div class="form-cell">
                    <!-- page specific plugin styles -->
                    <link rel="stylesheet" href="${request.contextPath!}/plugin/${className!}/dropzone/dropzone.min.css" />
                    <link rel="stylesheet" href="${request.contextPath!}/plugin/${className!}/node_modules/jquery-ui/themes/base/accordion.css"/>
                    <!--<script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/jquery/dist/jquery.min.js"/></script>-->
                    <script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/jquery-ui/dist/jquery-ui.min.js"/></script>
                    <script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/pdfjs-dist/build/pdf.js"/></script>
                    <script type="text/javascript" src="${request.contextPath}/plugin/${className}/node_modules/fabric/dist/fabric.min.js"/></script>
                    <style>
                        #pdfCanvas {
                          display:none;
                          border: 1px solid #ccc;
                        }

                        .accordion-header {
                          background-color: #eee;
                          cursor: pointer;
                          padding: 10px;
                        }

                        .accordion-content {
                          display: none;
                          padding: 10px;
                        }

                        .ui-accordion-header.ui-state-active {
                          /* Add your text styling for the active panel here */
                          font-weight: bold;
                          color: #454545;
                        }

                        .ui-accordion-header-icon.ui-state-active{
                          /* Add your text styling for the active panel here */
                          font-weight: bold;
                          color: #454545;
                        }
                    </style>
                    <div id="file-pdf" class="form-fileupload dropzone dz-clickable" style="width:'100%';"></div>
                    <!--<input name="file" type="file" id="file-pdf" multiple="false" class="form-fileupload dropzone dz-clickable" />-->

                    <!-- page specific plugin scripts -->
                    <script type="text/javascript" src="${request.contextPath}/plugin/${className}/dropzone/dropzone.min.js"></script>
                    <script type="text/javascript">
                        Dropzone.autoDiscover = false;
                        var myDropzone = new Dropzone("#file-pdf", {

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
                              document.getElementById('verify-result').style.display="none";
                              //console.log("File removed: " + file.name);
                            });

                            this.on("success", function (file, response) {
                              console.log("File uploaded successfully!");
                              document.getElementById('pdfCanvas').style.display="block";
                              //console.log(response.Data); // Log the server's response

                              var signData = response.Data;
                                if (Array.isArray(signData) && signData.length === 0) {
                                  console.log("Signature not found in "+ file.name);
                                } else {
                                  var result="";

                                  for (var i = 0; i < signData.length; i++) {
                                        var obj = signData[i];
                                        console.log("Signature Name :" + obj.signatureName)
                                        //console.log(obj.rootData);

                                        result +='<h4 class="accordion-header">'+ obj.signatureName+'</h4>';
                                        result +='<div class="accordion-content"><table><thead><tr><th> Certificate Detail</th></tr></thead><tbody><tr><td>';

                                        var innerArray = obj.rootData;
                                        for (var j = 0; j < innerArray.length; j++) {
                                          var innerObj = innerArray[j];
                                           result +='<table><tr><td>Subject</td><td>'+innerObj.subject+'</td></tr><tr><td>Certificate Status</td><td>'+innerObj.certificateStatus+'</td></tr><tr><td>Certificate Detail</td><td>'+innerObj.certificateDetail+'</td></tr><tr><td>Valid From</td><td>'+innerObj.validFrom+'</td></tr><tr><td>Valid To</td><td>'+innerObj.validTo+'</td></tr><tr><td>Issuer</td><td>'+innerObj.issuer+'</td></tr><tr><td colspan="2" style="background-color: #c5c5c5; height: 20px;"></td></tr></table>';
                                          //for (var key in innerObj) {
                                          //  console.log(key + ": " + innerObj[key]);
                                           // result +='<tr><td>'+ key + '</td><td>' + innerObj[key] +'</td></tr>';
                                          //}
                                        }
                                        result +='</td></tr></tbody></table></div>';
                                        console.log("----------------------");
                                    }

                                    var targetElement = document.getElementById('verify-result');
                                    targetElement.innerHTML = result;
                                    document.getElementById('verify-result').style.display="block";
                                    $("#verify-result").accordion();

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
                </div>
                <div class="form-cell">
                    <canvas id="pdfCanvas"></canvas>
                    <div id="verify-result"></div>
                </div>
                <div class="form-cell">

                </div>
            </div>
        </form>


    <div class="row">
        <div class="col-xs-12">
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
    </fieldset>

</div>
