document.addEventListener('DOMContentLoaded', function() {
    // Time range toggle
    var timeRangeSelect = document.getElementById('timeRange');
    if (timeRangeSelect) {
        timeRangeSelect.addEventListener('change', function() {
            var customRange = document.getElementById('customDateRange');
            if (this.value === 'custom') {
                customRange.style.display = 'flex';
            } else {
                customRange.style.display = 'none';
            }
        });
        
        // Trigger initial state
        timeRangeSelect.dispatchEvent(new Event('change'));
    }
    
    // Column toggle dropdown
    var columnToggleBtn = document.getElementById('columnToggleBtn');
    if (columnToggleBtn) {
        columnToggleBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            document.getElementById('columnToggleDropdown').classList.toggle('show');
        });
    }
    
    // Close dropdown when clicking outside
    window.addEventListener('click', function(e) {
        if (!e.target.matches('.dropdown-toggle')) {
            var dropdowns = document.getElementsByClassName('dropdown-content');
            for (var i = 0; i < dropdowns.length; i++) {
                var openDropdown = dropdowns[i];
                if (openDropdown.classList.contains('show')) {
                    openDropdown.classList.remove('show');
                }
            }
        }
    });
    
    // Toggle columns
    var checkboxes = document.querySelectorAll('#columnToggleDropdown input[type="checkbox"]');
    checkboxes.forEach(function(checkbox) {
        checkbox.addEventListener('change', function() {
            var colClass = this.id;
            var cells = document.querySelectorAll('.' + colClass);
            
            cells.forEach(function(cell) {
                if (checkbox.checked) {
                    cell.style.display = '';
                } else {
                    cell.style.display = 'none';
                }
            });
        });
    });
    
    // View toggle (Table/Raw)
    var viewButtons = document.querySelectorAll('.view-toggle button');
    viewButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            // Toggle active class
            viewButtons.forEach(function(btn) {
                btn.classList.remove('active');
            });
            this.classList.add('active');
            
            // Show selected view
            var view = this.getAttribute('data-view');
            var views = document.querySelectorAll('.log-view');
            views.forEach(function(viewElement) {
                viewElement.classList.remove('active');
            });
            document.getElementById(view + 'View').classList.add('active');
        });
    });
    
    // Message expansion
    var messageCells = document.querySelectorAll('.message-cell');
    messageCells.forEach(function(cell) {
        cell.addEventListener('click', function() {
            var fullMessage = this.getAttribute('data-full-message') || this.textContent;
            showModal('Full Message', '<pre>' + fullMessage + '</pre>');
        });
    });
    
    // View log buttons
    var logButtons = document.querySelectorAll('.view-log-btn');
    logButtons.forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            var logId = this.getAttribute('data-id');
            showLogDetails(logId);
        });
    });
    
    // Export button
    var exportBtn = document.getElementById('exportLogsBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            showExportModal();
        });
    }
    
    // Initialize charts if available
    if (typeof initializeCharts === 'function') {
        initializeCharts();
    }
});

// Generic modal function
function showModal(title, content) {
    var modal = document.createElement('div');
    modal.className = 'message-modal';
    modal.innerHTML = '<div class="message-modal-content">' +
        '<div class="message-modal-header">' +
        '<h3>' + title + '</h3>' +
        '<span class="close-modal">&times;</span>' +
        '</div>' +
        '<div class="message-modal-body">' + content + '</div>' +
        '</div>';
    
    document.body.appendChild(modal);
    
    modal.querySelector('.close-modal').addEventListener('click', function() {
        modal.remove();
    });
    
    modal.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.remove();
        }
    });
}

// Show log details
function showLogDetails(logId) {
    fetch('/SiemApp/log/' + logId + '/')
        .then(function(response) {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(function(log) {
            var content = '<div class="log-details">' +
                '<div class="detail-row"><div class="detail-label">ID:</div><div class="detail-value">' + log.id + '</div></div>' +
                '<div class="detail-row"><div class="detail-label">Timestamp:</div><div class="detail-value">' + log.timestamp + '</div></div>' +
                '<div class="detail-row"><div class="detail-label">Topic:</div><div class="detail-value">' + log.topic + '</div></div>' +
                '<div class="detail-row"><div class="detail-label">Publisher:</div><div class="detail-value">' + log.publisher_id + '</div></div>' +
                '<div class="detail-row"><div class="detail-label">IP Address:</div><div class="detail-value">' + (log.ip || 'Unknown') + '</div></div>' +
                '<div class="detail-row"><div class="detail-label">QoS:</div><div class="detail-value">' + log.qos + '</div></div>' +
                '<div class="detail-row"><div class="detail-label">Message:</div><div class="detail-value"><pre>' + log.message + '</pre></div></div>' +
                '</div>';
            
            showModal('Log Details', content);
        })
        .catch(function(error) {
            console.error('Error fetching log details:', error);
            showModal('Error', '<p>Failed to load log details</p>');
        });
}

// Show export modal
function showExportModal() {
    var content = '<form id="exportForm" action="/SiemApp/export-logs/" method="get">' +
        '<div class="form-group">' +
        '<label>Export Format</label>' +
        '<div class="radio-group">' +
        '<div class="radio-option">' +
        '<input type="radio" id="formatCSV" name="format" value="csv" checked>' +
        '<label for="formatCSV">CSV</label>' +
        '</div>' +
        '<div class="radio-option">' +
        '<input type="radio" id="formatJSON" name="format" value="json">' +
        '<label for="formatJSON">JSON</label>' +
        '</div>' +
        '</div>' +
        '</div>' +
        '<div class="form-actions">' +
        '<button type="submit" class="btn btn-primary">Export</button>' +
        '</div>' +
        '</form>';
    
    showModal('Export Logs', content);
}