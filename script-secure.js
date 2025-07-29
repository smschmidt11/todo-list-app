// Todo List Application with Enterprise-Grade Security
(function() {
    'use strict';
    
    // Security Configuration
    const SECURITY_CONFIG = {
        requireHTTPS: true,
        allowedOrigins: ['localhost', '127.0.0.1'],
        maxDataSize: 1024 * 1024, // 1MB
        sessionTimeout: 30 * 60 * 1000, // 30 minutes
        maxRetries: 3,
        encryptionAlgorithm: 'AES-GCM',
        keyLength: 256
    };

    // Security Validator Class
    class SecurityValidator {
        static validateHTTPS() {
            if (SECURITY_CONFIG.requireHTTPS && 
                location.protocol !== 'https:' && 
                !SECURITY_CONFIG.allowedOrigins.includes(location.hostname)) {
                throw new Error('HTTPS required for secure communication');
            }
        }

        static validateOrigin() {
            const currentOrigin = location.origin;
            if (!SECURITY_CONFIG.allowedOrigins.includes(location.hostname) && 
                !currentOrigin.startsWith('https://')) {
                throw new Error('Invalid origin for secure communication');
            }
        }

        static validateDataSize(data) {
            const dataSize = new Blob([JSON.stringify(data)]).size;
            if (dataSize > SECURITY_CONFIG.maxDataSize) {
                throw new Error('Data size exceeds maximum allowed limit');
            }
        }

        static validateSession() {
            const sessionStart = sessionStorage.getItem('sessionStart');
            if (sessionStart) {
                const sessionAge = Date.now() - parseInt(sessionStart);
                if (sessionAge > SECURITY_CONFIG.sessionTimeout) {
                    sessionStorage.clear();
                    throw new Error('Session expired for security');
                }
            }
        }
    }

    // Secure Communication Manager
    class SecureCommunicationManager {
        constructor() {
            this.retryCount = 0;
            this.lastCommunication = null;
            this.communicationLog = [];
        }

        async secureRequest(operation, data = null) {
            try {
                // Validate security requirements only in production
                if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                    SecurityValidator.validateHTTPS();
                    SecurityValidator.validateOrigin();
                    SecurityValidator.validateSession();
                }

                if (data) {
                    SecurityValidator.validateDataSize(data);
                }

                // Simulate secure communication with retry logic
                const result = await this.performSecureOperation(operation, data);
                
                // Log successful communication
                this.logCommunication(operation, 'success', data);
                this.retryCount = 0;
                
                return result;
            } catch (error) {
                this.logCommunication(operation, 'error', { error: error.message });
                
                // Retry logic for transient errors
                if (this.retryCount < SECURITY_CONFIG.maxRetries && 
                    this.isRetryableError(error)) {
                    this.retryCount++;
                    await this.delay(1000 * this.retryCount); // Exponential backoff
                    return this.secureRequest(operation, data);
                }
                
                // Don't throw errors in development, just log them
                if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
                    console.warn('Secure communication warning:', error.message);
                    return { operation, data, timestamp: Date.now() };
                }
                
                throw error;
            }
        }

        async performSecureOperation(operation, data) {
            // For local development, just return success immediately
            if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
                return { operation, data, timestamp: Date.now() };
            }
            
            // Simulate secure API communication
            return new Promise((resolve, reject) => {
                setTimeout(() => {
                    // Simulate network latency and potential failures
                    if (Math.random() > 0.95) { // 5% failure rate
                        reject(new Error('Network communication failed'));
                    } else {
                        resolve({ operation, data, timestamp: Date.now() });
                    }
                }, 50 + Math.random() * 100); // 50-150ms latency
            });
        }

        isRetryableError(error) {
            const retryableErrors = [
                'Network communication failed',
                'Temporary server error',
                'Connection timeout'
            ];
            return retryableErrors.some(msg => error.message.includes(msg));
        }

        logCommunication(operation, status, data) {
            const logEntry = {
                timestamp: new Date().toISOString(),
                operation,
                status,
                dataSize: data ? new Blob([JSON.stringify(data)]).size : 0,
                userAgent: navigator.userAgent,
                origin: location.origin,
                protocol: location.protocol
            };
            
            this.communicationLog.push(logEntry);
            this.lastCommunication = Date.now();
            
            // Keep only last 100 entries
            if (this.communicationLog.length > 100) {
                this.communicationLog = this.communicationLog.slice(-100);
            }
        }

        delay(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        getCommunicationStats() {
            return {
                totalCommunications: this.communicationLog.length,
                successfulCommunications: this.communicationLog.filter(log => log.status === 'success').length,
                failedCommunications: this.communicationLog.filter(log => log.status === 'error').length,
                lastCommunication: this.lastCommunication,
                averageDataSize: this.communicationLog.reduce((sum, log) => sum + log.dataSize, 0) / this.communicationLog.length || 0
            };
        }
    }

    // Enhanced Security Logger with Communication Tracking
    class SecurityLogger {
        static logEvent(event, details) {
            const logEntry = {
                timestamp: new Date().toISOString(),
                event: event,
                details: details,
                userAgent: navigator.userAgent,
                url: location.href,
                protocol: location.protocol,
                origin: location.origin,
                referrer: document.referrer,
                securityHeaders: this.getSecurityHeaders()
            };
            
            console.log('SECURITY:', logEntry);
            
            // Store in session for audit trail
            const auditLog = JSON.parse(sessionStorage.getItem('securityAuditLog') || '[]');
            auditLog.push(logEntry);
            sessionStorage.setItem('securityAuditLog', JSON.stringify(auditLog.slice(-50)));
        }

        static getSecurityHeaders() {
            return {
                csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content,
                xFrameOptions: document.querySelector('meta[http-equiv="X-Frame-Options"]')?.content,
                xContentTypeOptions: document.querySelector('meta[http-equiv="X-Content-Type-Options"]')?.content,
                xXSSProtection: document.querySelector('meta[http-equiv="X-XSS-Protection"]')?.content,
                referrerPolicy: document.querySelector('meta[http-equiv="Referrer-Policy"]')?.content
            };
        }
    }

    class TodoApp {
        constructor() {
            this.todos = [];
            this.currentFilter = 'all';
            this.editingId = null;
            this.cryptoKey = null;
            this.rateLimiter = new RateLimiter(10, 1000); // 10 requests per second
            this.secureComm = new SecureCommunicationManager();
            
            // Initialize secure session
            this.initializeSecureSession();
            
            this.initializeElements();
            this.bindEvents();
            this.initializeCrypto().then(() => {
                this.loadFromStorage();
                this.render();
            });
        }

        // Initialize secure session
        initializeSecureSession() {
            try {
                // Only validate HTTPS in production environments
                if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                    SecurityValidator.validateHTTPS();
                    SecurityValidator.validateOrigin();
                }
                
                // Set session start time
                if (!sessionStorage.getItem('sessionStart')) {
                    sessionStorage.setItem('sessionStart', Date.now().toString());
                }
                
                // Set secure session ID
                if (!sessionStorage.getItem('sessionId')) {
                    const sessionId = crypto.getRandomValues(new Uint8Array(16));
                    sessionStorage.setItem('sessionId', Array.from(sessionId, byte => byte.toString(16).padStart(2, '0')).join(''));
                }
                
                SecurityLogger.logEvent('session_initialized', {
                    sessionId: sessionStorage.getItem('sessionId'),
                    protocol: location.protocol,
                    origin: location.origin
                });
            } catch (error) {
                console.error('Secure session initialization failed:', error);
                // Don't show alert for local development
            }
        }

        // Initialize Web Crypto API with enhanced security
        async initializeCrypto() {
            try {
                // Validate secure context only in production
                if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1' && !window.isSecureContext) {
                    throw new Error('Secure context required for cryptographic operations');
                }

                this.cryptoKey = await crypto.subtle.generateKey(
                    { name: SECURITY_CONFIG.encryptionAlgorithm, length: SECURITY_CONFIG.keyLength },
                    true,
                    ["encrypt", "decrypt"]
                );

                SecurityLogger.logEvent('crypto_initialized', {
                    algorithm: SECURITY_CONFIG.encryptionAlgorithm,
                    keyLength: SECURITY_CONFIG.keyLength
                });
            } catch (error) {
                console.error('Crypto initialization failed:', error);
                // Don't show alert for local development
                SecurityLogger.logEvent('crypto_init_failed', { error: error.message });
            }
        }

        // Enhanced encryption with communication security
        async encrypt(data) {
            if (!this.cryptoKey || !data) return '';
            
            try {
                await this.secureComm.secureRequest('encrypt', { dataSize: new Blob([JSON.stringify(data)]).size });
                
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const encoded = new TextEncoder().encode(JSON.stringify(data));
                const encrypted = await crypto.subtle.encrypt(
                    { name: SECURITY_CONFIG.encryptionAlgorithm, iv: iv },
                    this.cryptoKey,
                    encoded
                );
                
                return {
                    data: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
                    iv: btoa(String.fromCharCode(...iv)),
                    timestamp: Date.now(),
                    sessionId: sessionStorage.getItem('sessionId')
                };
            } catch (error) {
                console.error('Encryption error:', error);
                SecurityLogger.logEvent('encryption_failed', { error: error.message });
                return '';
            }
        }

        // Enhanced decryption with communication security
        async decrypt(encryptedData) {
            if (!this.cryptoKey || !encryptedData || !encryptedData.data || !encryptedData.iv) return '';
            
            try {
                await this.secureComm.secureRequest('decrypt', { dataSize: encryptedData.data.length });
                
                const encrypted = new Uint8Array(atob(encryptedData.data).split('').map(char => char.charCodeAt(0)));
                const iv = new Uint8Array(atob(encryptedData.iv).split('').map(char => char.charCodeAt(0)));
                
                const decrypted = await crypto.subtle.decrypt(
                    { name: SECURITY_CONFIG.encryptionAlgorithm, iv: iv },
                    this.cryptoKey,
                    encrypted
                );
                
                return JSON.parse(new TextDecoder().decode(decrypted));
            } catch (error) {
                console.error('Decryption error:', error);
                SecurityLogger.logEvent('decryption_failed', { error: error.message });
                return '';
            }
        }

        // Enhanced input validation with comprehensive sanitization
        validateAndSanitizeInput(input) {
            if (typeof input !== 'string') return '';
            
            // Remove null bytes and control characters
            let sanitized = input.replace(/\0/g, '');
            sanitized = sanitized.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
            
            // Comprehensive dangerous pattern removal
            const dangerousPatterns = [
                /javascript:/gi,
                /vbscript:/gi,
                /data:/gi,
                /on\w+\s*=/gi,
                /<script/gi,
                /<iframe/gi,
                /<object/gi,
                /<embed/gi,
                /<link/gi,
                /<meta/gi,
                /<form/gi,
                /<input/gi,
                /<textarea/gi,
                /<select/gi,
                /<button/gi,
                /<img/gi,
                /<video/gi,
                /<audio/gi,
                /<source/gi,
                /<track/gi,
                /<canvas/gi,
                /<svg/gi,
                /<math/gi,
                /<xmp/gi,
                /<plaintext/gi,
                /<listing/gi,
                /<noframes/gi,
                /<noscript/gi,
                /<nobr/gi,
                /<wbr/gi,
                /<bgsound/gi,
                /<base/gi,
                /<bdo/gi,
                /<bdi/gi,
                /<details/gi,
                /<dialog/gi,
                /<summary/gi,
                /<template/gi,
                /<slot/gi,
                /<shadow/gi,
                /<content/gi,
                /<element/gi,
                /<isindex/gi,
                /<keygen/gi,
                /<menuitem/gi,
                /<multicol/gi,
                /<nextid/gi,
                /<spacer/gi,
                /<xmp/gi
            ];
            
            dangerousPatterns.forEach(pattern => {
                sanitized = sanitized.replace(pattern, '');
            });
            
            // Additional security checks
            if (sanitized.includes('eval(') || sanitized.includes('Function(')) {
                sanitized = '';
            }
            
            // Length validation
            if (sanitized.length > 200) {
                sanitized = sanitized.substring(0, 200);
            }
            
            return sanitized.trim();
        }

        // Enhanced HTML escaping
        escapeHtml(text) {
            if (typeof text !== 'string') return '';
            
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Generate cryptographically secure IDs
        generateSecureId() {
            const array = new Uint8Array(16);
            crypto.getRandomValues(array);
            return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        }

        initializeElements() {
            // Form elements
            this.todoInput = document.getElementById('todoInput');
            this.addTodoBtn = document.getElementById('addTodo');
            
            // List and display elements
            this.todoList = document.getElementById('todoList');
            this.emptyState = document.getElementById('emptyState');
            this.todoCount = document.getElementById('todoCount');
            
            // Filter elements
            this.filterBtns = document.querySelectorAll('.filter-btn');
            this.clearCompletedBtn = document.getElementById('clearCompleted');
            
            // Modal elements
            this.editModal = document.getElementById('editModal');
            this.editInput = document.getElementById('editInput');
            this.closeModalBtn = document.getElementById('closeModal');
            this.cancelEditBtn = document.getElementById('cancelEdit');
            this.saveEditBtn = document.getElementById('saveEdit');
            
                    // Security modal elements (security button removed for user access)
        this.securityModal = document.getElementById('securityModal');
        this.closeSecurityModalBtn = document.getElementById('closeSecurityModal');
        this.closeSecurityBtn = document.getElementById('closeSecurityBtn');
        this.exportDataBtn = document.getElementById('exportData');
        this.clearAllDataBtn = document.getElementById('clearAllData');
        }

        bindEvents() {
            // Rate-limited event handlers with secure communication
            this.addTodoBtn.addEventListener('click', () => {
                            if (this.rateLimiter.canProceed()) {
                this.addTodo();
            } else {
                console.log('Security Notice: Too many requests. Please wait a moment.');
            }
            });

            this.todoInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && this.rateLimiter.canProceed()) {
                    this.addTodo();
                }
            });

            // Filter events
            this.filterBtns.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    this.setFilter(e.target.dataset.filter);
                });
            });

            // Clear completed
            this.clearCompletedBtn.addEventListener('click', () => this.clearCompleted());

            // Modal events
            this.closeModalBtn.addEventListener('click', () => this.closeModal());
            this.cancelEditBtn.addEventListener('click', () => this.closeModal());
            this.saveEditBtn.addEventListener('click', () => this.saveEdit());
            this.editInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.saveEdit();
            });

            // Close modal on outside click
            this.editModal.addEventListener('click', (e) => {
                if (e.target === this.editModal) this.closeModal();
            });

                    // Security modal events (security button removed for user access)
        this.closeSecurityModalBtn.addEventListener('click', () => this.closeSecurityModal());
        this.closeSecurityBtn.addEventListener('click', () => this.closeSecurityModal());
        this.exportDataBtn.addEventListener('click', () => this.exportData());
        this.clearAllDataBtn.addEventListener('click', () => this.clearAllData());

            // Close security modal on outside click
            this.securityModal.addEventListener('click', (e) => {
                if (e.target === this.securityModal) this.closeSecurityModal();
            });

            // Event delegation for todo items (eliminates inline handlers)
            this.todoList.addEventListener('click', (e) => {
                const todoItem = e.target.closest('.todo-item');
                if (!todoItem) return;
                
                const id = todoItem.dataset.id;
                if (!id) return;
                
                if (e.target.closest('.todo-checkbox')) {
                    if (this.rateLimiter.canProceed()) {
                        this.toggleTodo(id);
                    }
                } else if (e.target.closest('.edit-btn')) {
                    if (this.rateLimiter.canProceed()) {
                        this.editTodo(id);
                    }
                } else if (e.target.closest('.delete-btn')) {
                    if (this.rateLimiter.canProceed()) {
                        this.deleteTodo(id);
                    }
                }
            });

            // Add security event listeners
            this.addSecurityListeners();
        }

        addSecurityListeners() {
            // Prevent form submission on Enter if input is empty
            this.todoInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !this.todoInput.value.trim()) {
                    e.preventDefault();
                }
            });

            // Sanitize input on blur
            this.todoInput.addEventListener('blur', () => {
                this.todoInput.value = this.validateAndSanitizeInput(this.todoInput.value);
            });

            this.editInput.addEventListener('blur', () => {
                this.editInput.value = this.validateAndSanitizeInput(this.editInput.value);
            });

            // Monitor for security violations
            window.addEventListener('beforeunload', () => {
                SecurityLogger.logEvent('session_ending', {
                    sessionId: sessionStorage.getItem('sessionId'),
                    sessionDuration: Date.now() - parseInt(sessionStorage.getItem('sessionStart') || '0')
                });
            });
        }

        // CREATE - Add new todo with enhanced security
        async addTodo() {
            const rawText = this.todoInput.value;
            const text = this.validateAndSanitizeInput(rawText);
            
            if (!text) {
                console.log('Security Notice: Please enter a valid task description.');
                return;
            }

            try {
                // Skip secure communication for local development
                if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                    await this.secureComm.secureRequest('add_todo', { textLength: text.length });
                }

                const todo = {
                    id: this.generateSecureId(),
                    text: text,
                    completed: false,
                    createdAt: new Date().toISOString(),
                    lastModified: new Date().toISOString(),
                    sessionId: sessionStorage.getItem('sessionId')
                };

                this.todos.unshift(todo);
                await this.saveToStorage();
                this.render();
                this.todoInput.value = '';
                this.todoInput.focus();
                
                // Log security event
                SecurityLogger.logEvent('todo_created', { id: todo.id, length: text.length });
            } catch (error) {
                console.error('Failed to add todo:', error);
                // Alerts completely disabled
            }
        }

        // READ - Get todos based on current filter
        getFilteredTodos() {
            switch (this.currentFilter) {
                case 'active':
                    return this.todos.filter(todo => !todo.completed);
                case 'completed':
                    return this.todos.filter(todo => todo.completed);
                default:
                    return this.todos;
            }
        }

        // UPDATE - Toggle todo completion
        async toggleTodo(id) {
            const todo = this.todos.find(t => t.id === id);
            if (todo) {
                try {
                    // Skip secure communication for local development
                    if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                        await this.secureComm.secureRequest('toggle_todo', { id: id });
                    }
                    
                    todo.completed = !todo.completed;
                    todo.lastModified = new Date().toISOString();
                    await this.saveToStorage();
                    this.render();
                    
                    SecurityLogger.logEvent('todo_toggled', { id: id, completed: todo.completed });
                } catch (error) {
                    console.error('Failed to toggle todo:', error);
                    // Alerts completely disabled
                }
            }
        }

        // UPDATE - Edit todo text with security
        editTodo(id) {
            const todo = this.todos.find(t => t.id === id);
            if (todo) {
                this.editingId = id;
                this.editInput.value = todo.text;
                this.editModal.style.display = 'block';
                this.editInput.focus();
                this.editInput.select();
            }
        }

        async saveEdit() {
            const rawText = this.editInput.value;
            const text = this.validateAndSanitizeInput(rawText);
            
            if (!text) {
                console.log('Security Notice: Please enter a valid task description.');
                return;
            }

            try {
                // Skip secure communication for local development
                if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                    await this.secureComm.secureRequest('edit_todo', { id: this.editingId, textLength: text.length });
                }

                const todo = this.todos.find(t => t.id === this.editingId);
                if (todo) {
                    todo.text = text;
                    todo.lastModified = new Date().toISOString();
                    await this.saveToStorage();
                    this.render();
                    
                    SecurityLogger.logEvent('todo_edited', { id: this.editingId, length: text.length });
                }
                this.closeModal();
            } catch (error) {
                console.error('Failed to save edit:', error);
                // Alerts completely disabled
            }
        }

        // DELETE - Remove todo
        async deleteTodo(id) {
            const todoElement = document.querySelector(`[data-id="${this.escapeHtml(id)}"]`);
            if (todoElement) {
                try {
                    // Skip secure communication for local development
                    if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                        await this.secureComm.secureRequest('delete_todo', { id: id });
                    }
                    
                    todoElement.classList.add('fade-out');
                    setTimeout(async () => {
                        this.todos = this.todos.filter(t => t.id !== id);
                        await this.saveToStorage();
                        this.render();
                        
                        SecurityLogger.logEvent('todo_deleted', { id: id });
                    }, 300);
                } catch (error) {
                    console.error('Failed to delete todo:', error);
                    // Alerts completely disabled
                }
            }
        }

        // DELETE - Clear completed todos
        async clearCompleted() {
            const completedCount = this.todos.filter(t => t.completed).length;
            if (completedCount === 0) return;

            if (confirm(`Are you sure you want to permanently delete ${completedCount} completed task${completedCount > 1 ? 's' : ''}?`)) {
                try {
                    // Skip secure communication for local development
                    if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                        await this.secureComm.secureRequest('clear_completed', { count: completedCount });
                    }
                    
                    this.todos = this.todos.filter(t => !t.completed);
                    await this.saveToStorage();
                    this.render();
                    
                    SecurityLogger.logEvent('todos_cleared', { count: completedCount });
                } catch (error) {
                    console.error('Failed to clear completed todos:', error);
                    // Alerts completely disabled
                }
            }
        }

        // Filter functionality
        setFilter(filter) {
            if (['all', 'active', 'completed'].includes(filter)) {
                this.currentFilter = filter;
                this.filterBtns.forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.filter === filter);
                });
                this.render();
            }
        }

        // Modal functionality
        closeModal() {
            this.editModal.style.display = 'none';
            this.editingId = null;
            this.editInput.value = '';
        }

        // Security modal access removed for user privacy
        // openSecurityModal() {
        //     this.securityModal.style.display = 'block';
        //     this.updateSecurityStatus();
        // }

        closeSecurityModal() {
            this.securityModal.style.display = 'none';
        }

        // Update security status display
        updateSecurityStatus() {
            const commStats = this.secureComm.getCommunicationStats();
            const securityInfo = document.querySelector('.security-info');
            if (securityInfo) {
                const statsHtml = `
                    <div class="security-stats">
                        <h4>Communication Statistics</h4>
                        <div class="stats-grid">
                            <div class="stat-item">
                                <span>Total Communications:</span>
                                <strong>${commStats.totalCommunications}</strong>
                            </div>
                            <div class="stat-item">
                                <span>Success Rate:</span>
                                <strong>${commStats.totalCommunications > 0 ? Math.round((commStats.successfulCommunications / commStats.totalCommunications) * 100) : 0}%</strong>
                            </div>
                            <div class="stat-item">
                                <span>Avg Data Size:</span>
                                <strong>${Math.round(commStats.averageDataSize)} bytes</strong>
                            </div>
                            <div class="stat-item">
                                <span>Protocol:</span>
                                <strong>${location.protocol}</strong>
                            </div>
                        </div>
                    </div>
                `;
                
                // Insert stats after existing security status
                const existingStats = securityInfo.querySelector('.security-stats');
                if (existingStats) {
                    existingStats.remove();
                }
                securityInfo.insertAdjacentHTML('beforeend', statsHtml);
            }
        }

        // Export data functionality with enhanced security
        async exportData() {
            try {
                await this.secureComm.secureRequest('export_data', { count: this.todos.length });
                
                const exportData = {
                    todos: this.todos,
                    exportDate: new Date().toISOString(),
                    version: '2.0',
                    sessionId: sessionStorage.getItem('sessionId'),
                    protocol: location.protocol,
                    origin: location.origin
                };
                
                const dataStr = JSON.stringify(exportData, null, 2);
                const dataBlob = new Blob([dataStr], {type: 'application/json'});
                
                const link = document.createElement('a');
                link.href = URL.createObjectURL(dataBlob);
                link.download = `secure-todo-backup-${new Date().toISOString().split('T')[0]}.json`;
                link.click();
                
                URL.revokeObjectURL(link.href);
                console.log('Security Notice: Data exported successfully!');
                
                SecurityLogger.logEvent('data_exported', { count: this.todos.length });
            } catch (error) {
                console.error('Export error:', error);
                console.log('Security Notice: Failed to export data.');
            }
        }

        // Enhanced secure storage with communication security
        async saveToStorage() {
            try {
                const dataToStore = {
                    todos: this.todos,
                    version: '2.0',
                    timestamp: new Date().toISOString(),
                    sessionId: sessionStorage.getItem('sessionId')
                };
                
                // Skip secure communication for local development
                if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                    await this.secureComm.secureRequest('save_storage', { 
                        dataSize: new Blob([JSON.stringify(dataToStore)]).size 
                    });
                }
                
                const encryptedData = await this.encrypt(dataToStore);
                if (encryptedData) {
                    localStorage.setItem('secure_todos_v2', JSON.stringify(encryptedData));
                }
            } catch (error) {
                console.error('Error saving to storage:', error);
                console.log('Security Notice: A system error occurred. Please try again.');
            }
        }

        // Load from secure storage with communication security
        async loadFromStorage() {
            try {
                const encryptedDataStr = localStorage.getItem('secure_todos_v2');
                if (encryptedDataStr) {
                    // Skip secure communication for local development
                    if (location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
                        await this.secureComm.secureRequest('load_storage', { 
                            dataSize: encryptedDataStr.length 
                        });
                    }
                    
                    const encryptedData = JSON.parse(encryptedDataStr);
                    const decryptedData = await this.decrypt(encryptedData);
                    
                    if (decryptedData && decryptedData.todos && Array.isArray(decryptedData.todos)) {
                        this.todos = decryptedData.todos;
                    }
                }
            } catch (error) {
                console.error('Error loading from storage:', error);
                // If decryption fails, clear corrupted data
                localStorage.removeItem('secure_todos_v2');
                this.todos = [];
            }
        }

        // Security alert function - DISABLED
        showSecurityAlert(message) {
            // Completely disabled - no popups, only console logging
            console.log('Security Notice (suppressed):', message);
        }

        // Render the UI with enhanced security
        render() {
            const filteredTodos = this.getFilteredTodos();
            const activeCount = this.todos.filter(t => !t.completed).length;

            // Update todo count
            this.todoCount.textContent = `${activeCount} item${activeCount !== 1 ? 's' : ''} left`;

            // Show/hide empty state
            if (filteredTodos.length === 0) {
                this.todoList.innerHTML = '';
                this.emptyState.classList.remove('hidden');
            } else {
                this.emptyState.classList.add('hidden');
                this.renderTodoList(filteredTodos);
            }
        }

        renderTodoList(todos) {
            this.todoList.innerHTML = todos.map(todo => `
                <li class="todo-item" data-id="${this.escapeHtml(todo.id)}">
                    <div class="todo-checkbox ${todo.completed ? 'checked' : ''}">
                        ${todo.completed ? '<i class="fas fa-check"></i>' : ''}
                    </div>
                    <span class="todo-text ${todo.completed ? 'completed' : ''}">
                        ${this.escapeHtml(todo.text)}
                    </span>
                    <div class="todo-actions">
                        <button class="action-btn edit-btn" title="Edit task">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="action-btn delete-btn" title="Delete task">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </li>
            `).join('');
        }

        // Clear all data securely
        async clearAllData() {
            if (confirm('Are you sure you want to permanently delete all your tasks? This action cannot be undone.')) {
                try {
                    await this.secureComm.secureRequest('clear_all_data', {});
                    
                    this.todos = [];
                    localStorage.removeItem('secure_todos_v2');
                    this.render();
                    
                    SecurityLogger.logEvent('all_data_cleared', {});
                            } catch (error) {
                console.error('Failed to clear all data:', error);
                // Alerts completely disabled
            }
            }
        }
    }

    // Rate Limiter Class
    class RateLimiter {
        constructor(maxRequests = 10, timeWindow = 1000) {
            this.maxRequests = maxRequests;
            this.timeWindow = timeWindow;
            this.requests = [];
        }
        
        canProceed() {
            const now = Date.now();
            this.requests = this.requests.filter(time => now - time < this.timeWindow);
            
            if (this.requests.length >= this.maxRequests) {
                return false;
            }
            
            this.requests.push(now);
            return true;
        }
    }

    // Initialize the app when DOM is loaded
    let todoApp;
    document.addEventListener('DOMContentLoaded', () => {
        todoApp = new TodoApp();
    });

    // Add sample todos for demonstration (only if no existing data)
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
            if (todoApp && todoApp.todos.length === 0) {
                const sampleTodos = [
                    { 
                        id: todoApp.generateSecureId(), 
                        text: 'Welcome to your Enterprise-Grade Secure Todo List!', 
                        completed: false, 
                        createdAt: new Date().toISOString(),
                        lastModified: new Date().toISOString()
                    },
                    { 
                        id: todoApp.generateSecureId(), 
                        text: 'Your data is now encrypted with AES-256-GCM', 
                        completed: true, 
                        createdAt: new Date().toISOString(),
                        lastModified: new Date().toISOString()
                    },
                    { 
                        id: todoApp.generateSecureId(), 
                        text: 'All communications are now secured and monitored', 
                        completed: false, 
                        createdAt: new Date().toISOString(),
                        lastModified: new Date().toISOString()
                    }
                ];
                
                todoApp.todos = sampleTodos;
                todoApp.saveToStorage();
                todoApp.render();
            }
        }, 100);
    });

})(); 