import './css/styles.css';
import { StateManager } from './js/state.js';
import { icon } from './js/ui.js';
import { initNavigation } from './js/components/sidebar.js';
import { EngineControl } from './js/components/engine-control.js';
import { Dashboard } from './js/components/dashboard.js';
import { RulesPanel } from './js/components/rules-panel.js';
import { ResultsView } from './js/components/results-table.js';
import { LogsView } from './js/components/logs.js';
import { initStatusMonitor } from './js/components/status.js';

document.querySelectorAll('[data-icon]').forEach(element => {
    element.innerHTML = icon(element.dataset.icon);
});
const state = new StateManager();
new Dashboard(state);
new EngineControl(state);
new RulesPanel(state);
new ResultsView(state);
new LogsView(state);
initStatusMonitor(state);
initNavigation();
state.refreshStatus();
state.refreshRules();
state.refreshHistory();
