rule OleStream {
    strings:
        $ole_magic = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole_stream = "\x01Ole10Native" wide

    condition:
        filename matches /word\/embeddings\/*/ and
        $ole_magic at 0 and $ole_stream
}
