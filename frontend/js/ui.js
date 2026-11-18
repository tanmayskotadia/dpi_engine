// Local SVGs keep the workspace usable without font or icon CDNs.
const paths = {
    layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/>',
    overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    sliders: '<path d="M4 7h9m4 0h3M4 17h3m4 0h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    list: '<path d="M9 6h12M9 12h12M9 18h12M3 6h.01M3 12h.01M3 18h.01"/>',
    terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
    arrowRight: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
    chevronRight: '<path d="m9 5 7 7-7 7"/>',
    upload: '<path d="M12 16V3m-5 5 5-5 5 5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
    download: '<path d="M12 3v13m-5-5 5 5 5-5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6Z"/><path d="M14 2v6h6M8 13h8m-8 4h5"/>',
    play: '<path d="m7 4 14 8-14 8V4Z"/>',
    stop: '<rect x="5" y="5" width="14" height="14" rx="1"/>',
    pause: '<path d="M8 4v16M16 4v16"/>',
    refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 7a7 7 0 0 1 11.5-2L20 8M4 16l2.4 3A7 7 0 0 0 18 17"/>',
    settings: '<path d="M12 3v3m0 12v3M3 12h3m12 0h3M6 6l2 2m8 8 2 2M6 18l2-2M16 8l2-2"/><circle cx="12" cy="12" r="5"/>',
    trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    link: '<path d="M10 13a4 4 0 0 0 6 .5l3-3a4 4 0 0 0-6-6l-2 2M14 11a4 4 0 0 0-6-.5l-3 3a4 4 0 0 0 6 6l2-2"/>',
    alert: '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v4m0 4h.01"/>',
    x: '<path d="m6 6 12 12M6 18 18 6"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    folder: '<path d="M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
    search: '<circle cx="10.5" cy="10.5" r="7.5"/><path d="m16 16 5 5"/>',
    filter: '<path d="M3 4h18l-7 8v7l-4 2v-9L3 4Z"/>',
    activity: '<path d="M2 12h5l3-8 4 16 3-8h5"/>',
    copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>',
    packets: '<path d="m12 3 9 5v8l-9 5-9-5V8l9-5Zm0 9v9M3 8l9 4 9-4M7.5 5.5l9 5"/>',
};
export function icon(name, size = 18) {
    return `<svg class="icon" width="${Number(size) || 18}" height="${Number(size) || 18}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${paths[name] || paths.info}</svg>`;
}
export function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}
export function formatNumber(value) { return (Number(value) || 0).toLocaleString(); }
export function formatBytes(value) {
    const bytes = Math.max(0, Number(value) || 0);
    if (!bytes) return '0 B';
    const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), 4);
    return `${(bytes / 1024 ** unit).toLocaleString(undefined, { maximumFractionDigits: unit ? 2 : 0 })} ${['B', 'KB', 'MB', 'GB', 'TB'][unit]}`;
}
export function formatDate(value) {
    if (!value) return 'Date unavailable';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Date unavailable' : date.toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
