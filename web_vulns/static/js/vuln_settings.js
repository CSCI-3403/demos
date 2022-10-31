Array.from(document.querySelectorAll('form[action="/vulns"] select')).forEach(element => {
    element.onchange = (e) => e.target.form.submit();
});