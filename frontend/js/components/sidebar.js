export function initNavigation() {
    const labels = { dashboard: 'Overview', engine: 'Analyze capture', results: 'Results', logs: 'Console' };
    const handleRoute = (event) => {
        let route = location.hash.slice(1);
        if (!Object.hasOwn(labels, route)) {
            route = 'dashboard';
            history.replaceState(null, '', '#dashboard');
        }
        document.querySelectorAll('.nav-item').forEach(item => {
            const active = item.dataset.target === route;
            item.classList.toggle('active', active);
            if (active) item.setAttribute('aria-current', 'page');
            else item.removeAttribute('aria-current');
        });
        document.querySelectorAll('.view-section').forEach(section => { section.hidden = section.id !== `view-${route}`; });
        document.getElementById('page-title').textContent = labels[route];
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
