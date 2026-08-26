export function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');
    const pageTitle = document.getElementById('page-title');

    const VALID_ROUTES = new Set(['dashboard', 'engine', 'results', 'logs']);

    // Hash routing
    const handleRoute = () => {
        let hash = window.location.hash.replace('#', '');

        // Fall back to dashboard for empty or unknown routes
        if (!hash || !VALID_ROUTES.has(hash)) {
            hash = 'dashboard';
            // Silently correct URL without pushing to history
            history.replaceState(null, '', '#dashboard');
        }

        navItems.forEach(item => {
            if (item.dataset.target === hash) {
                item.classList.add('active');
                // Extract only text nodes (skip icon text)
                const label = [...item.childNodes]
                    .filter(n => n.nodeType === Node.TEXT_NODE)
                    .map(n => n.textContent.trim())
                    .join('');
                pageTitle.textContent = label || item.textContent.trim();
            } else {
                item.classList.remove('active');
            }
        });

        sections.forEach(section => {
            if (section.id === `view-${hash}`) {
                section.classList.add('active');
            } else {
                section.classList.remove('active');
            }
        });
    };

    window.addEventListener('hashchange', handleRoute);
    handleRoute(); // initial
}
