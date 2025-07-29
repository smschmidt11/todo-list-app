// Todo List Application with Enterprise-Grade Security
(function() {
    'use strict';
    
    class TodoApp {
        constructor() {
            this.todos = [];
            this.currentFilter = 'all';
            this.editingId = null;
            this.cryptoKey = null;
            this.rateLimiter = new RateLimiter(10, 1000); // 10 requests per second
            
            this.initializeElements();
            this.bindEvents();
            this.initializeCrypto().then(() => {
                this.loadFromStorage();
                this.render();
            });
        }

        // Initialize Web Crypto API
        async initializeCrypto() {
            try {
                this.cryptoKey = await crypto.subtle.generateKey(
                    { name: "AES-GCM", length: 256 },
                    true,
                    ["encrypt", "decrypt"]
                );
            } catch (error) {
                console.error('Crypto initialization failed:', error);
                this.showSecurityAlert('Security initialization failed. Please refresh the page.');
            }
        }

        // Enterprise-grade encryption using Web Crypto API
        async encrypt(data) {
            if (!this.cryptoKey || !data) return '';
            
            try {
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const encoded = new TextEncoder().encode(JSON.stringify(data));
                const encrypted = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv },
                    this.cryptoKey,
                    encoded
                );
                
                return {
                    data: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
                    iv: btoa(String.fromCharCode(...iv))
                };
            } catch (error) {
                console.error('Encryption error:', error);
                return '';
            }
        }

        // Enterprise-grade decryption
        async decrypt(encryptedData) {
            if (!this.cryptoKey || !encryptedData || !encryptedData.data || !encryptedData.iv) return '';
            
            try {
                const encrypted = new Uint8Array(atob(encryptedData.data).split('').map(char => char.charCodeAt(0)));
                const iv = new Uint8Array(atob(encryptedData.iv).split('').map(char => char.charCodeAt(0)));
                
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    this.cryptoKey,
                    encrypted
                );
                
                return JSON.parse(new TextDecoder().decode(decrypted));
            } catch (error) {
                console.error('Decryption error:', error);
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
            
            // Security modal elements
            this.securityModal = document.getElementById('securityModal');
            this.securitySettingsBtn = document.getElementById('securitySettings');
            this.closeSecurityModalBtn = document.getElementById('closeSecurityModal');
            this.closeSecurityBtn = document.getElementById('closeSecurityBtn');
            this.exportDataBtn = document.getElementById('exportData');
            this.clearAllDataBtn = document.getElementById('clearAllData');
        }

        bindEvents() {
            // Rate-limited event handlers
            this.addTodoBtn.addEventListener('click', () => {
                if (this.rateLimiter.canProceed()) {
                    this.addTodo();
                } else {
                    this.showSecurityAlert('Too many requests. Please wait a moment.');
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

            // Security modal events
            this.securitySettingsBtn.addEventListener('click', () => this.openSecurityModal());
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
        }

        // CREATE - Add new todo with enhanced security
        addTodo() {
            const rawText = this.todoInput.value;
            const text = this.validateAndSanitizeInput(rawText);
            
            if (!text) {
                this.showSecurityAlert('Please enter a valid task description.');
                return;
            }

            const todo = {
                id: this.generateSecureId(),
                text: text,
                completed: false,
                createdAt: new Date().toISOString(),
                lastModified: new Date().toISOString()
            };

            this.todos.unshift(todo);
            this.saveToStorage();
            this.render();
            this.todoInput.value = '';
            this.todoInput.focus();
            
            // Log security event
            SecurityLogger.logEvent('todo_created', { id: todo.id, length: text.length });
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
        toggleTodo(id) {
            const todo = this.todos.find(t => t.id === id);
            if (todo) {
                todo.completed = !todo.completed;
                todo.lastModified = new Date().toISOString();
                this.saveToStorage();
                this.render();
                
                SecurityLogger.logEvent('todo_toggled', { id: id, completed: todo.completed });
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

        saveEdit() {
            const rawText = this.editInput.value;
            const text = this.validateAndSanitizeInput(rawText);
            
            if (!text) {
                this.showSecurityAlert('Please enter a valid task description.');
                return;
            }

            const todo = this.todos.find(t => t.id === this.editingId);
            if (todo) {
                todo.text = text;
                todo.lastModified = new Date().toISOString();
                this.saveToStorage();
                this.render();
                
                SecurityLogger.logEvent('todo_edited', { id: this.editingId, length: text.length });
            }
            this.closeModal();
        }

        // DELETE - Remove todo
        deleteTodo(id) {
            const todoElement = document.querySelector(`[data-id="${this.escapeHtml(id)}"]`);
            if (todoElement) {
                todoElement.classList.add('fade-out');
                setTimeout(() => {
                    this.todos = this.todos.filter(t => t.id !== id);
                    this.saveToStorage();
                    this.render();
                    
                    SecurityLogger.logEvent('todo_deleted', { id: id });
                }, 300);
            }
        }

        // DELETE - Clear completed todos
        clearCompleted() {
            const completedCount = this.todos.filter(t => t.completed).length;
            if (completedCount === 0) return;

            if (confirm(`Are you sure you want to permanently delete ${completedCount} completed task${completedCount > 1 ? 's' : ''}?`)) {
                this.todos = this.todos.filter(t => !t.completed);
                this.saveToStorage();
                this.render();
                
                SecurityLogger.logEvent('todos_cleared', { count: completedCount });
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

        openSecurityModal() {
            this.securityModal.style.display = 'block';
        }

        closeSecurityModal() {
            this.securityModal.style.display = 'none';
        }

        // Export data functionality
        exportData() {
            try {
                const exportData = {
                    todos: this.todos,
                    exportDate: new Date().toISOString(),
                    version: '2.0'
                };
                
                const dataStr = JSON.stringify(exportData, null, 2);
                const dataBlob = new Blob([dataStr], {type: 'application/json'});
                
                const link = document.createElement('a');
                link.href = URL.createObjectURL(dataBlob);
                link.download = `todo-list-backup-${new Date().toISOString().split('T')[0]}.json`;
                link.click();
                
                URL.revokeObjectURL(link.href);
                this.showSecurityAlert('Data exported successfully!');
                
                SecurityLogger.logEvent('data_exported', { count: this.todos.length });
            } catch (error) {
                console.error('Export error:', error);
                this.showSecurityAlert('Failed to export data.');
            }
        }

        // Enhanced secure storage
        async saveToStorage() {
            try {
                const dataToStore = {
                    todos: this.todos,
                    version: '2.0',
                    timestamp: new Date().toISOString()
                };
                
                const encryptedData = await this.encrypt(dataToStore);
                if (encryptedData) {
                    localStorage.setItem('secure_todos_v2', JSON.stringify(encryptedData));
                }
            } catch (error) {
                console.error('Error saving to storage:', error);
                this.showSecurityAlert('A system error occurred. Please try again.');
            }
        }

        // Load from secure storage
        async loadFromStorage() {
            try {
                const encryptedDataStr = localStorage.getItem('secure_todos_v2');
                if (encryptedDataStr) {
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

        // Security alert function
        showSecurityAlert(message) {
            const alert = document.createElement('div');
            alert.className = 'security-alert';
            alert.textContent = message;
            alert.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #dc3545;
                color: white;
                padding: 12px 20px;
                border-radius: 8px;
                z-index: 10000;
                font-weight: 500;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            `;
            
            document.body.appendChild(alert);
            
            setTimeout(() => {
                alert.remove();
            }, 3000);
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
        clearAllData() {
            if (confirm('Are you sure you want to permanently delete all your tasks? This action cannot be undone.')) {
                this.todos = [];
                localStorage.removeItem('secure_todos_v2');
                this.render();
                
                SecurityLogger.logEvent('all_data_cleared', {});
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

    // Security Logger Class
    class SecurityLogger {
        static logEvent(event, details) {
            const logEntry = {
                timestamp: new Date().toISOString(),
                event: event,
                details: details,
                userAgent: navigator.userAgent,
                url: location.href
            };
            
            console.log('SECURITY:', logEntry);
            
            // In production, send to server
            // this.sendToServer(logEntry);
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
                        text: 'All inputs are comprehensively validated and sanitized', 
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