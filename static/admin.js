(function(){
  function showToast(title, message){
    var t = document.getElementById("toast");
    if(!t) return;
    t.querySelector(".t").textContent = title || "Notice";
    t.querySelector(".m").textContent = message || "";
    t.classList.add("show");
    clearTimeout(t._hideTimer);
    t._hideTimer = setTimeout(function(){ t.classList.remove("show"); }, 4500);
  }

  function extractAllUrls(text){
    if(!text) return [];
    var m = text.match(/https?:\/\/[^\s"'<>()]+/ig);
    return m ? m : [];
  }

  // Confirm dialogs for destructive actions.
  document.addEventListener("click", function(ev){
    var el = ev.target;
    if(!el) return;
    if(el.closest) el = el.closest("[data-confirm]") || el;
    var msg = el && el.getAttribute ? el.getAttribute("data-confirm") : null;
    if(msg){
      if(!confirm(msg)){
        ev.preventDefault();
        ev.stopPropagation();
      }
    }
  }, true);

  // QR-only copy button: only appears when result contains a URL.
  var resultBox = document.getElementById("resultBox");
  var qrCopyBtn = document.getElementById("btnCopyQR");
  function refreshQrCopy(){
    if(!resultBox || !qrCopyBtn) return;
    var urls = extractAllUrls(resultBox.textContent || "");
    if(urls.length){
      qrCopyBtn.style.display = "";
      // Copy all detected QR URLs, one per line.
      qrCopyBtn._url = urls.join("\n");
    }else{
      qrCopyBtn.style.display = "none";
      qrCopyBtn._url = null;
    }
  }
  refreshQrCopy();

  if(qrCopyBtn){
    qrCopyBtn.addEventListener("click", async function(ev){
      ev.preventDefault();
      var url = qrCopyBtn._url;
      if(!url){
        showToast("Nothing to copy", "No QR link detected in the result.");
        return;
      }
      try{
        await navigator.clipboard.writeText(url);
        showToast("Copied", "QR link copied to clipboard.");
      }catch(e){
        // Fallback for older browsers / restricted clipboard.
        try{
          var ta = document.createElement("textarea");
          ta.value = url;
          ta.style.position = "fixed";
          ta.style.left = "-9999px";
          document.body.appendChild(ta);
          ta.focus();
          ta.select();
          var ok = document.execCommand("copy");
          document.body.removeChild(ta);
          if(ok){
            showToast("Copied", "QR link copied to clipboard.");
          }else{
            throw new Error("copy failed");
          }
        }catch(e2){
          showToast("Copy failed", "Could not access clipboard. Please copy manually.");
        }
      }
    });
  }

  // Show flash message from server (if injected).
  var flash = document.body.getAttribute("data-flash");
  if(flash){
    try{
      var obj = JSON.parse(flash);
      if(obj && (obj.title || obj.message)){
        showToast(obj.title || "Notice", obj.message || "");
      }
    }catch(e){}
  }
})();
