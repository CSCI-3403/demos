Array.from(document.getElementsByClassName("autosubmit")).forEach(element => {
    element.onclick = (e) => e.target.form.submit();
});