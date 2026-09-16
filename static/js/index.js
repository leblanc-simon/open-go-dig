function q(d){document.getElementById('query').value=d;document.querySelector('form').submit()}

// The picker submits one `type` value per checked box. The default chip (value
// "") and the per-type chips say opposite things — "let the server pick" vs.
// "exactly these" — so they cancel each other out, and emptying the selection
// falls back to the default chip rather than to nothing. Without JS the server
// still copes: an empty value alongside real types is simply dropped.
(function () {
    const boxes = Array.from(document.querySelectorAll('.type-sel input[name="type"]'));
    const fallback = boxes.find(b => b.value === '');
    if (!fallback) return;

    boxes.forEach(box => box.addEventListener('change', () => {
        if (box === fallback) {
            if (box.checked) boxes.forEach(o => { if (o !== fallback) o.checked = false; });
        } else if (box.checked) {
            fallback.checked = false;
        }
        if (!boxes.some(o => o.checked)) fallback.checked = true;
    }));
})();
