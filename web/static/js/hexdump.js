
/*
 * hexy js - https://github.com/a2800276/hexy.js
 *  modified for cuckoo/web
*/

var hexy = function (buffer, config) {
  var h = new Hexy(buffer, config)
  return h.toString()
}

var Hexy = function (buffer, config) {
  var self = this

  config = config || {}
 
  self.buffer    = buffer // magic string conversion here?
  self.width     = config.width || 16
  self.numbering = config.numbering == "none"  ? "none" : "hex_bytes"
   
  switch (config.format) {
    case "none":
    case "twos":
      self.format = config.format
      break
    default:
      self.format = "fours"
  }
  
  self.caps        = config.caps        == "upper" ? "upper" : "lower"
  self.annotate    = config.annotate    == "none"  ? "none"  : "ascii"
  self.prefix      = config.prefix      || ""
  self.indent      = config.indent      || 0
  self.html        = config.html        || false
  self.offset      = config.offset      || 0
  self.length      = config.length      || -1
  
  self.display_offset = config.display_offset || 0

  if (self.offset) {
    if (self.offset < self.buffer.length) {
      self.buffer = self.buffer.slice(self.offset)
    }
  }

  if (self.length !== -1) {
    if (self.length <= self.buffer.length) {
      self.buffer = self.buffer.slice(0,self.length)
    }
  }

  for (var i = 0; i!=self.indent; ++i) {
    self.prefix = " "+self.prefix
  }

  var pos = 0

  this.toString = function () {
    var str = ""
    
    if (self.html) { str += "<div class='hexy'>\n"}
    //split up into line of max `self.width`
    var line_arr = lines()
    
    //lines().forEach(function(hex_raw, i)
    for (var i = 0; i!= line_arr.length; ++i) {
      var hex_raw = line_arr[i],
          hex = hex_raw[0],
          raw = hex_raw[1]
      //insert spaces every `self.format.twos` or fours
      var howMany = hex.length
      if (self.format === "fours") {
        howMany = 4
      } else if (self.format === "twos") {
        howMany = 2
      }

      var hex_formatted = ""


      for (var j =0; j< hex.length; j+=howMany) {
        var s = hex.substr(j, howMany)
        hex_formatted += s + " "
      } 

      var addr = (i*self.width)+self.offset+self.display_offset;
      if (self.html) {
        odd = i%2 == 0 ? " even" : "  odd"
        str += "<div class='"+pad(addr, 8)+odd+"'>"
      }
      str += self.prefix 

      if (self.numbering === "hex_bytes") {
        str += pad(addr, 8) // padding...
        str += ": "
      }
      
      var padlen = 0
      switch(self.format) {
        case "fours":
          padlen = self.width*2 + self.width/2
          break
        case "twos":
          padlen = self.width*3 + 2
          break
        default:
          padlen = self.width * 2 + 1
      }

      str += rpad(hex_formatted, padlen)
      if (self.annotate === "ascii") {
        str+=" "
        var ascii = raw.replace(/[\000-\040\177-\377]/g, ".")
        str += escape(ascii)
      }
      if (self.html) {
        str += "</div>\n"
      } else {
      str += "\n"
      } 
    }
    if (self.html) { str += "</div>\n"}
    return str
  }

  var lines = function() {
    var hex_raw = []
    for (var i = 0; i<self.buffer.length ; i+=self.width) {
      var begin = i,
          end   = i+self.width >= self.buffer.length ? self.buffer.length : i+self.width,
          slice = self.buffer.slice(begin, end),
          hex   = self.caps === "upper" ? hexu(slice) : hexl(slice),
          raw   = slice.toString('ascii')

      hex_raw.push([hex,raw])
    }
    return hex_raw

  }

  var hexl = function (buffer) {
    var str = ""
    for (var i=0; i!=buffer.length; ++i) {
      if (buffer.constructor == String) {
        str += pad(buffer.charCodeAt(i), 2)
      } else {
        str += pad(buffer[i], 2)
      }
    }
    return str
  }
  var hexu = function (buffer) {
    return hexl(buffer).toUpperCase()
  }

  var pad = function(b, len) {
    var s = b.toString(16)
    
    while (s.length < len) {
      s = "0" + s
    }
    return s
  } 
  var rpad = function(s, len) {
    for (var n = len - s.length; n!=0; --n) {
      if (self.html) {
        s += "&nbsp;"
      } else {
        s += " "
      }
    
    }
    return s
  }

  var escape = function (str) {
    str = str.split("&").join("&amp;")
    str = str.split("<").join("&lt;")
    str = str.split(">").join("&gt;")
    return str
  }
  

}

/**
 * the following code is hacked up from the jquery base64 codec plugin
 *  removed 80% of its guts though...
 * jQuery Plugin - base64 codec
 * @lisence MIT License https://github.com/yatt/jquery.base64/blob/master/license.txt
 * @author yatt/brainfs http://d.hatena.ne.jp/yatt http://twitter.com/brainfs
 * @version 0.0.1
 * @info
 */

var base64 = new function()
// 
{
    var utfLibName  = "utf";
    var b64char     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var b64encTable = b64char.split("");
    var b64decTable = [];
    for (var i=0; i<b64char.length; i++) b64decTable[b64char.charAt(i)] = i;
    
    this.decode = function(_b64, _strMode)
    {
        var tmp = decoder( _b64 );
        var i, str = "";
        for (i in tmp) str += String.fromCharCode(tmp[i]);
        return str;
    }
    
    var decoder = function(_b64)
    {
        _b64    = _b64.replace(/[^A-Za-z0-9\+\/]/g, "");
        var md  = _b64.length % 4;
        var j, i, tmp;
        var dat = [];
        
        // replace 時 = も削っている。その = の代わりに 0x0 を補間
        if (md) for (i=0; i<4-md; i++) _b64 += "A";
        
        for (j=i=0; i<_b64.length; i+=4, j+=3)
        {
            tmp = (b64decTable[_b64.charAt( i )] <<18)
                | (b64decTable[_b64.charAt(i+1)] <<12)
                | (b64decTable[_b64.charAt(i+2)] << 6)
                |  b64decTable[_b64.charAt(i+3)];
            dat[ j ]    = tmp >>> 16;
            dat[j+1]    = (tmp >>> 8) & 0xff;
            dat[j+2]    = tmp & 0xff;
        }
        // 補完された 0x0 分削る
        if (md) dat.length -= [0,0,2,1][md];

        return dat;
    }

}
