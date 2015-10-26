' http://www.motobit.com/tips/detpg_read-write-binary-files/
Function SaveBinaryData(FileName, ByteArray)
    Const adTypeBinary = 1
    Const adSaveCreateOverWrite = 2

    ' create Stream object
    dim BinaryStream
    set BinaryStream = CreateObject("ADODB.Stream")

    ' specify stream type - we want to save binary data.
    BinaryStream.Type = adTypeBinary

    ' open the stream and write binary data To the object
    BinaryStream.Open
    BinaryStream.Write ByteArray

    ' save binary data to disk
    BinaryStream.SaveToFile FileName, adSaveCreateOverWrite
End Function

' http://stackoverflow.com/questions/5907089/how-to-post-https-request-using-vbscript
Function DownloadFile(FileName, Url)
    dim http
    set http = createobject("MSXML2.ServerXMLHTTP")

    http.Open "GET", Url, False

    ' 2 stands for SXH_OPTION_IGNORE_SERVER_SSL_CERT_ERROR_FLAGS
    ' 13056 means ignore all server side cert error
    http.setOption 2, 13056
    http.Send

    ' read response body
    SaveBinaryData FileName, http.responseBody
End Function

DownloadFile "index.html", "http://google.com/"
