/**
 * TVM Reporter Desktop App - Frontend Logic
 */

// File state
const fileState = {
    vulns: null,
    recs: null,
    software: null,
    events: null
};

// Output folder
let outputFolder = null;

// Result output directory (set after processing)
let resultOutputDir = null;

/**
 * Initialize the application
 */
document.addEventListener('DOMContentLoaded', function() {
    setupFileInputs();
    setupDragAndDrop();
});

/**
 * Setup file input handlers
 */
function setupFileInputs() {
    const fileTypes = ['vulns', 'recs', 'software', 'events'];

    fileTypes.forEach(type => {
        const input = document.getElementById(`${type}-input`);
        if (input) {
            input.addEventListener('change', function(e) {
                handleFileSelect(type, e.target.files[0]);
            });
        }
    });
}

/**
 * Setup drag and drop functionality
 */
function setupDragAndDrop() {
    const fileTypes = ['vulns', 'recs', 'software', 'events'];

    fileTypes.forEach(type => {
        const dropZone = document.getElementById(`${type}-drop`);
        if (dropZone) {
            dropZone.addEventListener('dragover', function(e) {
                e.preventDefault();
                e.stopPropagation();
                this.classList.add('drag-over');
            });

            dropZone.addEventListener('dragleave', function(e) {
                e.preventDefault();
                e.stopPropagation();
                this.classList.remove('drag-over');
            });

            dropZone.addEventListener('drop', function(e) {
                e.preventDefault();
                e.stopPropagation();
                this.classList.remove('drag-over');

                if (e.dataTransfer.files.length > 0) {
                    const file = e.dataTransfer.files[0];
                    if (file.name.endsWith('.csv')) {
                        handleFileSelect(type, file);
                    } else {
                        alert('Please select a CSV file');
                    }
                }
            });
        }
    });
}

/**
 * Handle file selection (click)
 */
function selectFile(type) {
    const input = document.getElementById(`${type}-input`);
    if (input) {
        input.click();
    }
}

/**
 * Handle file selected
 */
function handleFileSelect(type, file) {
    if (!file) return;

    // Store file path (for Electron/Eel, we need the actual path)
    // In browser context, we use the File object
    fileState[type] = file.path || file.name;

    // Update UI
    const card = document.getElementById(`${type}-card`);
    const nameSpan = document.getElementById(`${type}-name`);

    if (card) {
        card.classList.add('has-file');
    }

    if (nameSpan) {
        nameSpan.textContent = file.name;
    }
}

/**
 * Select output folder using native dialog
 */
async function selectOutputFolder() {
    try {
        const folder = await eel.select_output_folder()();
        if (folder) {
            outputFolder = folder;
            document.getElementById('output-folder').value = folder;
        }
    } catch (error) {
        console.error('Error selecting folder:', error);
    }
}

/**
 * Validate required files are selected
 */
function validateFiles() {
    const required = ['vulns', 'recs', 'software'];
    const missing = required.filter(type => !fileState[type]);

    if (missing.length > 0) {
        const names = {
            'vulns': 'Vulnerabilities CSV',
            'recs': 'Recommendations CSV',
            'software': 'Software Inventory CSV'
        };
        const missingNames = missing.map(m => names[m]).join(', ');
        alert(`Please select the required files: ${missingNames}`);
        return false;
    }

    return true;
}

/**
 * Get file paths from file inputs
 */
function getFilePaths() {
    const paths = {};
    const fileTypes = ['vulns', 'recs', 'software', 'events'];

    fileTypes.forEach(type => {
        const input = document.getElementById(`${type}-input`);
        if (input && input.files.length > 0) {
            // Get the actual file path
            const file = input.files[0];
            paths[type] = file.path || null;
        }
    });

    return paths;
}

/**
 * Process reports - main action
 */
async function processReports() {
    // Validate files
    const paths = getFilePaths();

    if (!paths.vulns || !paths.recs || !paths.software) {
        alert('Please select all required CSV files (Vulnerabilities, Recommendations, Software Inventory)');
        return;
    }

    // Get options
    const profileMode = document.getElementById('profile-mode').checked;
    const strictMode = document.getElementById('strict-mode').checked;
    const sinceDateInput = document.getElementById('since-date').value;
    const sinceDate = sinceDateInput || null;

    // Show progress section
    showSection('progress');

    // Disable process button
    document.getElementById('process-btn').disabled = true;

    try {
        // Start processing
        const result = await eel.process_reports(
            paths.vulns,
            paths.recs,
            paths.software,
            paths.events || null,
            outputFolder,
            profileMode,
            strictMode,
            sinceDate
        )();

        // Start polling for progress
        pollProgress();

        // Handle result
        if (result.success) {
            resultOutputDir = result.output_dir;
            showResults(result.summary);
        } else {
            showError(result.error);
        }

    } catch (error) {
        console.error('Processing error:', error);
        showError(error.message || 'An unexpected error occurred');
    }

    // Re-enable process button
    document.getElementById('process-btn').disabled = false;
}

/**
 * Poll for processing progress
 */
async function pollProgress() {
    try {
        const state = await eel.get_processing_state()();

        // Update progress bar
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');

        if (progressFill) {
            progressFill.style.width = `${state.progress}%`;
        }

        if (progressText) {
            progressText.textContent = state.status;
        }

        // Continue polling if not complete and no error
        if (!state.complete && !state.error) {
            setTimeout(pollProgress, 500);
        }

    } catch (error) {
        console.error('Error polling progress:', error);
    }
}

/**
 * Show results section with summary data
 */
function showResults(summary) {
    showSection('results');

    const grid = document.getElementById('results-grid');
    grid.innerHTML = `
        <div class="result-card">
            <div class="result-value">${summary.total_cves || 0}</div>
            <div class="result-label">Total CVEs</div>
        </div>
        <div class="result-card">
            <div class="result-value">${summary.total_devices || 0}</div>
            <div class="result-label">Total Devices</div>
        </div>
        <div class="result-card">
            <div class="result-value">${summary.total_products || 0}</div>
            <div class="result-label">Total Products</div>
        </div>
        <div class="result-card critical">
            <div class="result-value">${summary.critical_count || 0}</div>
            <div class="result-label">Critical</div>
        </div>
        <div class="result-card high">
            <div class="result-value">${summary.high_count || 0}</div>
            <div class="result-label">High</div>
        </div>
        <div class="result-card medium">
            <div class="result-value">${summary.medium_count || 0}</div>
            <div class="result-label">Medium</div>
        </div>
        <div class="result-card low">
            <div class="result-value">${summary.low_count || 0}</div>
            <div class="result-label">Low</div>
        </div>
    `;
}

/**
 * Show error section
 */
function showError(message) {
    showSection('error');
    document.getElementById('error-message').textContent = message;
}

/**
 * Show a specific section (hide others)
 */
function showSection(section) {
    const sections = ['progress', 'results', 'error'];

    sections.forEach(s => {
        const el = document.getElementById(`${s}-section`);
        if (el) {
            el.style.display = (s === section) ? 'block' : 'none';
        }
    });
}

/**
 * Open the output folder in file explorer
 */
async function openOutputFolder() {
    if (resultOutputDir) {
        try {
            await eel.open_folder(resultOutputDir)();
        } catch (error) {
            console.error('Error opening folder:', error);
            alert('Could not open folder: ' + error.message);
        }
    }
}

/**
 * Reset form for new processing
 */
function resetForm() {
    // Clear file state
    Object.keys(fileState).forEach(key => {
        fileState[key] = null;
    });

    // Reset file inputs
    const fileTypes = ['vulns', 'recs', 'software', 'events'];
    fileTypes.forEach(type => {
        const input = document.getElementById(`${type}-input`);
        const card = document.getElementById(`${type}-card`);
        const nameSpan = document.getElementById(`${type}-name`);

        if (input) input.value = '';
        if (card) card.classList.remove('has-file');
        if (nameSpan) nameSpan.textContent = 'No file selected';
    });

    // Reset options
    document.getElementById('profile-mode').checked = false;
    document.getElementById('strict-mode').checked = false;
    document.getElementById('since-date').value = '';
    document.getElementById('output-folder').value = '';

    // Reset output folder
    outputFolder = null;
    resultOutputDir = null;

    // Reset progress
    const progressFill = document.getElementById('progress-fill');
    if (progressFill) progressFill.style.width = '0%';

    // Hide all result/progress/error sections
    showSection(null);

    // Re-enable process button
    document.getElementById('process-btn').disabled = false;
}
