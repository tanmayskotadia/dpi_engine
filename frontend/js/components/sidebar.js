export function initNavigation() {
    const toggle = document.getElementById('nav-toggle');
    const index = document.getElementById('workspace-index');
    const links = [...index.querySelectorAll('.nav-item')];
    const labels = Object.fromEntries(links.map(link => [link.dataset.target, link.textContent.trim()]));
    const compact = window.matchMedia('(max-width: 600px)');
    const closeIndex = () => toggle.setAttribute('aria-expanded', 'false');
    toggle.addEventListener('click', () => {
        toggle.setAttribute('aria-expanded', String(toggle.getAttribute('aria-expanded') !== 'true'));
    });
    document.addEventListener('click', event => {
        if (!toggle.contains(event.target) && !index.contains(event.target)) closeIndex();
    });
    document.addEventListener('focusin', event => {
        if (!toggle.contains(event.target) && !index.contains(event.target)) closeIndex();
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') {
            closeIndex();
            toggle.focus();
        }
    });
    compact.addEventListener('change', closeIndex);
    index.addEventListener('click', event => {
        if (compact.matches && event.target.closest('a[href]')) {
            closeIndex();
            toggle.focus({ preventScroll: true });
        }
    });
    const handleRoute = (event) => {
        let route = location.hash.slice(1);
        if (!Object.hasOwn(labels, route)) {
            route = 'dashboard';
            history.replaceState(null, '', '#dashboard');
        }
        closeIndex();
        links.forEach(item => {
            const active = item.dataset.target === route;
            item.classList.toggle('active', active);
            if (active) item.setAttribute('aria-current', 'page');
            else item.removeAttribute('aria-current');
        });
        document.querySelectorAll('.view-section').forEach(section => { section.hidden = section.id !== `view-${route}`; });
        document.getElementById('nav-current').textContent = labels[route];
        document.title = `${labels[route]} · DPI Engine`;
        if (event) {
            document.getElementById('main-content').focus({ preventScroll: true });
            window.scrollTo({ top: 0, behavior: 'instant' });
        }
    };
    window.addEventListener('hashchange', handleRoute);
    document.querySelector('.skip-link').addEventListener('click', event => {
        event.preventDefault();
        document.getElementById('main-content').focus();
    });
    handleRoute();
}
