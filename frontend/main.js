import './css/styles.css';
import { api } from './js/api.js';
import { StateManager } from './js/state.js';
import { initNavigation } from './js/components/sidebar.js';
import { EngineControl } from './js/components/engine-control.js';
import { Dashboard } from './js/components/dashboard.js';
import { RulesPanel } from './js/components/rules-panel.js';
import { ResultsView } from './js/components/results-table.js';
import { LogsView } from './js/components/logs.js';
import { initStatusMonitor } from './js/components/status.js';

document.addEventListener('DOMContentLoaded', () => {
    // Initialize state
    const state = new StateManager();

    // Initialize UI components
    initNavigation();
    initStatusMonitor(state);
    
    const dashboard = new Dashboard(state);
    const engineControl = new EngineControl(state);
    const rulesPanel = new RulesPanel(state);
    const resultsView = new ResultsView(state);
    const logsView = new LogsView(state);

    // Initial data fetch
    state.refreshStatus();
    state.refreshRules();
    state.refreshHistory();
});
