function showHide(id, lbl) {
    var e = document.getElementById(id);

    if (lbl !== "undefined")
        var l = document.getElementById(lbl);

    if(e.style.display == "none") {
        e.style.display = "block";
        if (l) {
            l.innerHTML = "Collapse";
        }
    }
    else {
        e.style.display = "none";
        if (l)
            l.innerHTML = "Expand";
    }
}
