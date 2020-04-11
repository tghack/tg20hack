document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("btn").addEventListener("click", () => {
        let xhr = new XMLHttpRequest();
        xhr.open("post", window.location.href, true);
        xhr.onreadystatechange = () => {
            if (xhr.readyState == 4 && xhr.status == 200) {
                document.location.reload(true);
            }
        };
        xhr.send(document.getElementById("text").value);
    });
});
