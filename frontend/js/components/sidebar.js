export function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');
    const pageTitle = document.getElementById('page-title');
    
    // Hash routing
    const handleRoute = () => {
        let hash = window.location.hash.replace('#', '') || 'dashboard';
        
        navItems.forEach(item => {
            if (item.dataset.target === hash) {
                item.classList.add('active');
                pageTitle.textContent = item.textContent.trim();
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
