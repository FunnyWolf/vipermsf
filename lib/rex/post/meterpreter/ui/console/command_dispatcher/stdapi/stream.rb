# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
  module Post
    module Meterpreter
      module Ui

        module Console::CommandDispatcher::Stdapi::Stream

          def stream_html_template(name, host, stream_path)
            html = %|<html>
<head>
<META HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
<META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
<title>Metasploit #{name} - #{host}</title>
<script language="javascript">
function updateStatus(msg) {
  var status = document.getElementById("status");
  status.innerText = msg;
}

function noImage() {
  document.getElementById("streamer").style = "display:none";
  updateStatus("Waiting");
}

function updateFrame() {
  var img = document.getElementById("streamer");
  const timestamp = new Date().getTime();
  img.src = "#{stream_path}?t=" + timestamp;
  img.style = "display:";
  updateStatus("Playing");
}

setInterval(function() {
  updateFrame();
},500);

</script>
</head>
<body>
<noscript>
  <h2><font color="red">Error: You need Javascript enabled to watch the stream.</font></h2>
</noscript>
<pre>
Target IP  : #{host}
Start time : #{::Time.now}
Status     : <span id="status"></span>
</pre>
<br>
<img onerror="noImage()" id="streamer">
<br><br>
</body>
</html>
    |
            html
          end
        end
      end
    end
  end
end
