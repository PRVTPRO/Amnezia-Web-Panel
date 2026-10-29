(() => {
    const nav = document.querySelector('.settings-nav');
    const anchor = document.getElementById('settings-nav-anchor');
    if (!nav || !anchor || typeof IntersectionObserver === 'undefined') return;

    // Observe the original slot, not the sticky nav: its own bounds stop moving.
    const observer = new IntersectionObserver(([entry]) => {
        nav.classList.toggle('is-stuck', !entry.isIntersecting && entry.boundingClientRect.top < 0);
    });
    observer.observe(anchor);
})();
