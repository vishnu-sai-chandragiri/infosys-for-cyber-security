// Main JavaScript for Cybersecurity AI System

// Global variables
let socket;
let isConnected = false;
let reconnectAttempts = 0;
const maxReconnectAttempts = 5;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    setupGlobalEventListeners();
    updateConnectionStatus();
    checkAuthentication();
});

// Socket.IO initialization
function initializeSocket() {
    try {
        socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to server');
            isConnected = true;
            reconnectAttempts = 0;
            updateConnectionStatus();
            showNotification('Connected to cybersecurity system', 'success');
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from server');
            isConnected = false;
            updateConnectionStatus();
            showNotification('Disconnected from server', 'warning');
        });
        
        socket.on('connect_error', function(error) {
            console.error('Connection error:', error);
            isConnected = false;
            updateConnectionStatus();
            
            if (reconnectAttempts < maxReconnectAttempts) {
                reconnectAttempts++;
                showNotification(`Connection failed. Retrying... (${reconnectAttempts}/${maxReconnectAttempts})`, 'warning');
            } else {
                showNotification('Unable to connect to server. Please check your connection.', 'danger');
            }
        });
        
        socket.on('status', function(data) {
            console.log('Status update:', data);
        });
        
        socket.on('error', function(data) {
            console.error('Server error:', data);
            showNotification(`Server error: ${data.message}`, 'danger');
        });
        
    } catch (error) {
        console.error('Failed to initialize socket:', error);
        showNotification('Failed to connect to real-time features', 'warning');
    }
}

// Global event listeners
function setupGlobalEventListeners() {
    // Handle page visibility changes
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            // Page is hidden, pause updates
            console.log('Page hidden, pausing updates');
        } else {
            // Page is visible, resume updates
            console.log('Page visible, resuming updates');
            if (isConnected) {
                // Request fresh data
                requestFreshData();
            }
        }
    });
    
    // Handle window resize
    window.addEventListener('resize', function() {
        // Debounce resize events
        clearTimeout(window.resizeTimeout);
        window.resizeTimeout = setTimeout(function() {
            handleWindowResize();
        }, 250);
    });
    
    // Handle keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        handleKeyboardShortcuts(e);
    });
}

// Update connection status indicator
function updateConnectionStatus() {
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    
    if (statusIndicator && statusText) {
        if (isConnected) {
            statusIndicator.className = 'fas fa-circle text-success';
            statusText.textContent = 'Connected';
        } else {
            statusIndicator.className = 'fas fa-circle text-danger';
            statusText.textContent = 'Disconnected';
        }
    }
}

// Show notification
function showNotification(message, type = 'info', duration = 5000) {
    // Remove existing notifications of the same type
    const existingNotifications = document.querySelectorAll(`.notification-${type}`);
    existingNotifications.forEach(notification => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    });
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${getNotificationIcon(type)}"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after duration
    setTimeout(() => {
        if (notification.parentNode) {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }
    }, duration);
}

// Get notification icon based on type
function getNotificationIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle',
        'error': 'times-circle'
    };
    return icons[type] || 'info-circle';
}

// Request fresh data from server
function requestFreshData() {
    if (socket && isConnected) {
        // Request different types of data based on current page
        const currentPage = window.location.pathname;
        
        if (currentPage === '/' || currentPage === '/dashboard') {
            socket.emit('request_threats');
        }
        // Add more page-specific requests as needed
    }
}

// Handle window resize
function handleWindowResize() {
    // Update charts if they exist
    if (window.threatChart) {
        window.threatChart.resize();
    }
    if (window.threatTypeChart) {
        window.threatTypeChart.resize();
    }
    
    // Update any other responsive elements
    updateResponsiveElements();
}

// Update responsive elements
function updateResponsiveElements() {
    // Update chat messages height
    const chatMessages = document.getElementById('chat-messages');
    if (chatMessages) {
        const windowHeight = window.innerHeight;
        const newHeight = Math.min(400, windowHeight * 0.4);
        chatMessages.style.height = `${newHeight}px`;
    }
}

// Handle keyboard shortcuts
function handleKeyboardShortcuts(e) {
    // Ctrl/Cmd + K: Focus search/input
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const input = document.getElementById('chat-input') || document.querySelector('input[type="text"]');
        if (input) {
            input.focus();
        }
    }
    
    // Escape: Close modals
    if (e.key === 'Escape') {
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(modal => {
            const modalInstance = bootstrap.Modal.getInstance(modal);
            if (modalInstance) {
                modalInstance.hide();
            }
        });
    }
    
    // Ctrl/Cmd + R: Refresh data (prevent default page reload)
    if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
        e.preventDefault();
        requestFreshData();
        showNotification('Data refreshed', 'info', 2000);
    }
}

// Utility functions
const Utils = {
    // Format numbers with commas
    formatNumber: function(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    },
    
    // Format bytes
    formatBytes: function(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },
    
    // Format time duration
    formatDuration: function(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    },
    
    // Format timestamp
    formatTimestamp: function(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) { // Less than 1 minute
            return 'Just now';
        } else if (diff < 3600000) { // Less than 1 hour
            const minutes = Math.floor(diff / 60000);
            return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
        } else if (diff < 86400000) { // Less than 1 day
            const hours = Math.floor(diff / 3600000);
            return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        } else {
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        }
    },
    
    // Get severity color
    getSeverityColor: function(severity) {
        const colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        };
        return colors[severity.toLowerCase()] || 'secondary';
    },
    
    // Debounce function
    debounce: function(func, wait, immediate) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                timeout = null;
                if (!immediate) func(...args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func(...args);
        };
    },
    
    // Throttle function
    throttle: function(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
};

// Chart utilities
const ChartUtils = {
    // Default chart options
    defaultOptions: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    usePointStyle: true,
                    padding: 20
                }
            }
        },
        scales: {
            x: {
                grid: {
                    display: false
                }
            },
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(0,0,0,0.1)'
                }
            }
        }
    },
    
    // Color palette
    colors: [
        '#FF6384',
        '#36A2EB',
        '#FFCE56',
        '#4BC0C0',
        '#9966FF',
        '#FF9F40',
        '#FF6384',
        '#C9CBCF',
        '#4BC0C0',
        '#FF6384'
    ],
    
    // Create gradient
    createGradient: function(ctx, color1, color2) {
        const gradient = ctx.createLinearGradient(0, 0, 0, 400);
        gradient.addColorStop(0, color1);
        gradient.addColorStop(1, color2);
        return gradient;
    }
};

// API utilities
const API = {
    // Generic API call
    call: async function(url, options = {}) {
        try {
            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API call failed:', error);
            throw error;
        }
    },
    
    // GET request
    get: function(url) {
        return this.call(url, { method: 'GET' });
    },
    
    // POST request
    post: function(url, data) {
        return this.call(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },
    
    // PUT request
    put: function(url, data) {
        return this.call(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },
    
    // DELETE request
    delete: function(url) {
        return this.call(url, { method: 'DELETE' });
    }
};

// Authentication functions
function checkAuthentication() {
    const token = localStorage.getItem('auth_token');
    const userInfo = localStorage.getItem('user_info');
    
    if (token && userInfo) {
        try {
            const user = JSON.parse(userInfo);
            showAuthenticatedUser(user);
        } catch (error) {
            console.error('Error parsing user info:', error);
            clearAuthentication();
        }
    } else {
        showUnauthenticatedUser();
    }
}

function showAuthenticatedUser(user) {
    const authNav = document.getElementById('auth-nav');
    const loginNav = document.getElementById('login-nav');
    const userName = document.getElementById('user-name');
    
    if (authNav && loginNav) {
        authNav.style.display = 'block';
        loginNav.style.display = 'none';
    }
    
    if (userName) {
        userName.textContent = user.firstName || user.email;
    }
    
    // Setup logout functionality
    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
        logoutLink.addEventListener('click', handleLogout);
    }
}

function showUnauthenticatedUser() {
    const authNav = document.getElementById('auth-nav');
    const loginNav = document.getElementById('login-nav');
    
    if (authNav && loginNav) {
        authNav.style.display = 'none';
        loginNav.style.display = 'block';
    }
}

function handleLogout(e) {
    e.preventDefault();
    
    // Call logout API
    fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        clearAuthentication();
        showNotification('Logged out successfully', 'success');
        
        // Redirect to login page if not already there
        if (window.location.pathname !== '/login') {
            window.location.href = '/login';
        }
    })
    .catch(error => {
        console.error('Logout error:', error);
        clearAuthentication();
        showNotification('Logged out', 'info');
    });
}

function clearAuthentication() {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
    showUnauthenticatedUser();
}

// Export for use in other scripts
window.Utils = Utils;
window.ChartUtils = ChartUtils;
window.API = API;
window.showNotification = showNotification;
window.checkAuthentication = checkAuthentication;



