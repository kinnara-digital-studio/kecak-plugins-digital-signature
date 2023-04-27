# REST Web API

## Get OTP

### Plugin Type
Plugin Web Service

### Overview
Generate OTP token. 

System triggers `otp` process flow and send the otp token using email / sms / push notification as configured in the process flow.

OTP token will be stored in form `otp` along with current username.

### Request

##### Url
`/web/json/plugin/com.kinnara.kecakplugins.digitalsignature.webapi.GetOtpApi/service`

##### Method
**GET**

##### Authorization
**required** - Basic / Bearer

### Response

#### Status code
- 201 - Success, token has been created
- 400 - Error generating OTP
- 401 - Authorization required

## Get QR Code

### Plugin Type
Plugin Web Service

### Overview
Generate QR Code image in PNG format.

### Request

##### Url
`/web/json/plugin/com.kinnara.kecakplugins.digitalsignature.webapi.GetQrCodeApi/service`

##### Method
**GET**

##### Parameters
- content : **required** - QR code content

##### Authorization
**required** - Basic / Bearer

## Get Signature

### Plugin Type
Plugin Web Service

### Overview
Retrieve signature file from directory wflow/app_certificate/_username_/signature.png

### Request

##### Url
`/web/json/plugin/com.kinnara.kecakplugins.digitalsignature.webapi.GetSignatureApi/service`

##### Method
**GET**

##### Authorization
**required** - Basic / Bearer

## Get Time Stamp

### Plugin Type
Plugin Web Service

### Overview
Request for time stamp to TSA.

### Request

#### Url
`/web/json/plugin/com.kinnara.kecakplugins.digitalsignature.webapi.GetTimeStampApi/service`

##### Method
**POST**

##### Authorization
**optional** - Anonymous

##### Content-Type
- **application/timestamp-query** - TSQ

### Response

##### Content-Type
- **application/timestamp-reply** - TSR

## Sign

### Plugin Type
Plugin Web Service

### Overview
Sign a PDF file.

### Request

##### Url
`/web/json/plugin/com.kinnara.kecakplugins.digitalsignature.webapi.SignApi/service`

#### Method
**POST**

## Verify

### Plugin Type
Plugin Web Service

### Overview
Verify PDF file

### Request

##### Url
`/web/json/plugin/com.kinnara.kecakplugins.digitalsignature.webapi.VerifyApi/service`

#### Method
**POST**
