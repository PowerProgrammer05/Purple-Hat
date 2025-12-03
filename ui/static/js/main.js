/**
 * PURPLE HAT - Main JavaScript
 * Client-side functionality for web interface
 */

// Utility functions
const Utils = {
    /**
     * Format bytes to human readable size
     */
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    /**
     * Format date to readable string
     */
    formatDate(date) {
        return new Date(date).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    /**
     * Show notification
     */
    notify(message, type = 'info') {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;
        
        const container = document.querySelector('.container');
        if (container) {
            container.insertBefore(alert, container.firstChild);
            setTimeout(() => alert.remove(), 5000);
        }
    },

    /**
     * Copy text to clipboard
     */
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.notify('Copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Failed to copy:', err);
        });
    },

    /**
     * Deep clone object
     */
    deepClone(obj) {
        return JSON.parse(JSON.stringify(obj));
    }
};

// API functions
const API = {
    baseUrl: '/api',

    /**
     * Generic fetch wrapper
     */
    async request(endpoint, method = 'GET', data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, options);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    /**
     * GET request
     */
    get(endpoint) {
        return this.request(endpoint, 'GET');
    },

    /**
     * POST request
     */
    post(endpoint, data) {
        return this.request(endpoint, 'POST', data);
    },

    /**
     * PUT request
     */
    put(endpoint, data) {
        return this.request(endpoint, 'PUT', data);
    },

    /**
     * DELETE request
     */
    delete(endpoint) {
        return this.request(endpoint, 'DELETE');
    }
};

// Scanning modes
const ScanningModes = {
    /**
     * Load available modes
     */
    async loadModes() {
        try {
            return await API.get('/config/modes');
        } catch (error) {
            Utils.notify('Failed to load scanning modes', 'danger');
            throw error;
        }
    },

    /**
     * Set active mode
     */
    async setMode(modeId) {
        try {
            return await API.post('/config/set-mode', { mode: modeId });
        } catch (error) {
            Utils.notify('Failed to set scanning mode', 'danger');
            throw error;
        }
    },

    /**
     * Update configuration
     */
    async updateConfig(config) {
        try {
            return await API.post('/config/update', config);
        } catch (error) {
            Utils.notify('Failed to update configuration', 'danger');
            throw error;
        }
    }
};

// Scan operations
const Scanning = {
    /**
     * Start a new scan
     */
    async startScan(target, modules) {
        try {
            return await API.post('/scan/start', {
                target,
                modules
            });
        } catch (error) {
            Utils.notify('Failed to start scan', 'danger');
            throw error;
        }
    },

    /**
     * Get scan details
     */
    async getScan(scanId) {
        try {
            return await API.get(`/scan/${scanId}`);
        } catch (error) {
            Utils.notify('Failed to retrieve scan details', 'danger');
            throw error;
        }
    },

    /**
     * Get all results
     */
    async getResults() {
        try {
            return await API.get('/results');
        } catch (error) {
            Utils.notify('Failed to retrieve results', 'danger');
            throw error;
        }
    },

    /**
     * Generate report
     */
    async generateReport(scanId, format = 'html') {
        try {
            return await API.post('/report/generate', {
                scan_id: scanId,
                format
            });
        } catch (error) {
            Utils.notify('Failed to generate report', 'danger');
            throw error;
        }
    }
};

// Results management
const Results = {
    /**
     * Format vulnerability severity
     */
    getSeverityBadge(severity) {
        const severityMap = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'warning',
            'low': 'info',
            'info': 'info'
        };
        return severityMap[severity?.toLowerCase()] || 'info';
    },

    /**
     * Display vulnerability details
     */
    displayVulnerability(vuln) {
        return `
            <div class="card">
                <h4>${vuln.title}</h4>
                <p><strong>Type:</strong> ${vuln.type}</p>
                <p><strong>Severity:</strong> <span class="badge badge-${this.getSeverityBadge(vuln.severity)}">${vuln.severity}</span></p>
                <p><strong>Description:</strong> ${vuln.description}</p>
                ${vuln.payload ? `<p><strong>Payload:</strong> <code>${vuln.payload}</code></p>` : ''}
                ${vuln.remediation ? `<p><strong>Remediation:</strong> ${vuln.remediation}</p>` : ''}
            </div>
        `;
    }
};

// Event handlers
const Events = {
    /**
     * Setup global event listeners
     */
    init() {
        // Handle page load
        document.addEventListener('DOMContentLoaded', () => {
            this.setupNavigation();
            this.setupForms();
        });
    },

    /**
     * Setup navigation
     */
    setupNavigation() {
        const navLinks = document.querySelectorAll('nav a');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            });
        });
    },

    /**
     * Setup form handlers
     */
    setupForms() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(form);
                const data = Object.fromEntries(formData);
                
                // Handle form submission based on form ID
            // Setup delegated click handlers for action buttons
            this.setupDelegates();
                const formId = form.id;

        /**
         * Setup delegated click handlers for dynamic UI buttons
         */
        setupDelegates() {
            document.addEventListener('click', (e) => {
                const btn = e.target.closest('button');
                if (!btn) return;
                const action = btn.dataset.action;
                if (!action) return;
                switch (action) {
                    case 'copy-payload': {
                        const payload = btn.dataset.payload || '';
                        if (payload) {
                            Utils.copyToClipboard(payload);
                        } else {
                            Utils.notify('No payload to copy', 'warning');
                        }
                        break;
                    }
                    case 'copy-reverse-shell':
                    case 'copy-webshell':
                    case 'copy-encoded': {
                        const targetId = btn.dataset.target;
                        if (targetId) {
                            const text = document.getElementById(targetId)?.textContent || '';
                            Utils.copyToClipboard(text);
                        }
                        break;
                    }
                    case 'download-webshell': {
                        // Use the same logic as downloadWebShell()
                        const code = document.getElementById('webshell-code').textContent;
                        const type = document.getElementById('webshell-type').value;
                        const ext = {
                            'php_simple': '.php',
                            'php_advanced': '.php',
                            'aspx': '.aspx',
                            'jsp': '.jsp'
                        }[type];
                        const blob = new Blob([code], { type: 'text/plain' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `shell${ext}`;
                        a.click();
                        break;
                    }
                    case 'generate-reverse-shell': {
                        window.generateReverseShell && window.generateReverseShell();
                        break;
                    }
                    case 'generate-web-shell': {
                        window.generateWebShell && window.generateWebShell();
                        break;
                    }
                    case 'get-payloads': {
                        window.getPayloads && window.getPayloads();
                        break;
                    }
                    case 'get-escalation-payloads': {
                        window.getEscalationPayloads && window.getEscalationPayloads();
                        break;
                    }
                    case 'encode-payload': {
                        window.encodePayload && window.encodePayload();
                        break;
                    }
                    case 'generate-exfil': {
                        window.generateExfil && window.generateExfil();
                        break;
                    }
                    case 'generate-report': {
                        window.generateReport && window.generateReport();
                        break;
                    }
                    case 'export-csv': {
                        window.exportCsv && window.exportCsv();
                        break;
                    }
                    case 'delete-scan': {
                        window.deleteScan && window.deleteScan();
                        break;
                    }
                    case 'view-details': {
                        const id = btn.dataset.id;
                        if (id && window.viewDetails) {
                            window.viewDetails(id);
                        }
                        break;
                    }
                    default: {
                        // Handle other delegated actions as needed
                        break;
                    }
                }
            });
        },
                if (formId === 'scanForm') {
                    await this.handleScanForm(data);
                } else if (formId === 'configForm') {
                    await this.handleConfigForm(data);
                }
            });
        });
    },

    /**
     * Handle scan form submission
     */
    async handleScanForm(data) {
        try {
            const result = await Scanning.startScan(data.target, data.modules);
            Utils.notify('Scan started successfully', 'success');
        } catch (error) {
            console.error('Error submitting scan form:', error);
        }
    },

    /**
     * Handle configuration form submission
     */
    async handleConfigForm(data) {
        try {
            const result = await ScanningModes.updateConfig(data);
            Utils.notify('Configuration updated successfully', 'success');
        } catch (error) {
            console.error('Error updating configuration:', error);
        }
    }
};

// Initialize on load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => Events.init());
} else {
    Events.init();
}

// Export for use in other scripts
window.PurpleHat = {
    Utils,
    API,
    ScanningModes,
    Scanning,
    Results
};
