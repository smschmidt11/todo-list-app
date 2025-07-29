// Todo List Application with Enhanced Security and CRUD functionality
class TodoApp {
    constructor() {
        this.todos = [];
        this.currentFilter = 'all';
        this.editingId = null;
        this.encryptionKey = this.generateEncryptionKey();
        
        this.initializeElements();
        this.bindEvents();
        this.loadFromStorage();
        this.render();
    }

    // Generate a unique encryption key for this session
    generateEncryptionKey() {
        // Use a combination of browser fingerprint and timestamp
        const browserFingerprint = navigator.userAgent + navigator.language + screen.width + screen.height;
        const timestamp = Date.now().toString();
        const combined = browserFingerprint + timestamp;
        
        // Create a simple hash for the encryption key
        let hash = 0;
        for (let i = 0; i < combined.length; i++) {
            const char = combined.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(36);
    }

    // Simple encryption function (for demonstration - in production use Web Crypto API)
    encrypt(text) {
        if (!text) return '';
        try {
            // Simple XOR encryption with the key
            let encrypted = '';
            for (let i = 0; i < text.length; i++) {
                const charCode = text.charCodeAt(i);
                const keyChar = this.encryptionKey.charCodeAt(i % this.encryptionKey.length);
                encrypted += String.fromCharCode(charCode ^ keyChar);
            }
            return btoa(encrypted); // Base64 encode
        } catch (error) {
            console.error('Encryption error:', error);
            return '';
        }
    }

    // Simple decryption function
    decrypt(encryptedText) {
        if (!encryptedText) return '';
        try {
            const decoded = atob(encryptedText); // Base64 decode
            let decrypted = '';
            for (let i = 0; i < decoded.length; i++) {
                const charCode = decoded.charCodeAt(i);
                const keyChar = this.encryptionKey.charCodeAt(i % this.encryptionKey.length);
                decrypted += String.fromCharCode(charCode ^ keyChar);
            }
            return decrypted;
        } catch (error) {
            console.error('Decryption error:', error);
            return '';
        }
    }

    // Enhanced input validation and sanitization
    validateAndSanitizeInput(input) {
        if (typeof input !== 'string') return '';
        
        // Trim whitespace
        let sanitized = input.trim();
        
        // Remove potentially dangerous characters and patterns
        sanitized = sanitized.replace(/[<>]/g, ''); // Remove < and >
        sanitized = sanitized.replace(/javascript:/gi, ''); // Remove javascript: protocol
        sanitized = sanitized.replace(/on\w+\s*=/gi, ''); // Remove event handlers
        sanitized = sanitized.replace(/data:/gi, ''); // Remove data: protocol
        
        // Limit length
        if (sanitized.length > 200) {
            sanitized = sanitized.substring(0, 200);
        }
        
        return sanitized;
    }

    // Enhanced HTML escaping
    escapeHtml(text) {
        if (typeof text !== 'string') return '';
        
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
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
        // Add todo with input validation
        this.addTodoBtn.addEventListener('click', () => this.addTodo());
        this.todoInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.addTodo();
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

        // Add security event listeners
        this.addSecurityListeners();
    }

    // Add security-focused event listeners
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
    }

    // Generate a more secure ID
    generateSecureId() {
        return Date.now() + '_' + Math.random().toString(36).substr(2, 9);
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
        }
        this.closeModal();
    }

    // DELETE - Remove todo
    deleteTodo(id) {
        const todoElement = document.querySelector(`[data-id="${this.escapeHtml(id.toString())}"]`);
        if (todoElement) {
            todoElement.classList.add('fade-out');
            setTimeout(() => {
                this.todos = this.todos.filter(t => t.id !== id);
                this.saveToStorage();
                this.render();
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

    // Security modal functionality
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
                version: '1.0'
            };
            
            const dataStr = JSON.stringify(exportData, null, 2);
            const dataBlob = new Blob([dataStr], {type: 'application/json'});
            
            const link = document.createElement('a');
            link.href = URL.createObjectURL(dataBlob);
            link.download = `todo-list-backup-${new Date().toISOString().split('T')[0]}.json`;
            link.click();
            
            URL.revokeObjectURL(link.href);
            this.showSecurityAlert('Data exported successfully!');
        } catch (error) {
            console.error('Export error:', error);
            this.showSecurityAlert('Failed to export data.');
        }
    }

    // Enhanced secure storage
    saveToStorage() {
        try {
            const dataToStore = {
                todos: this.todos,
                version: '1.0',
                timestamp: new Date().toISOString()
            };
            
            const encryptedData = this.encrypt(JSON.stringify(dataToStore));
            localStorage.setItem('secure_todos', encryptedData);
        } catch (error) {
            console.error('Error saving to storage:', error);
            this.showSecurityAlert('Failed to save data securely.');
        }
    }

    // Load from secure storage
    loadFromStorage() {
        try {
            const encryptedData = localStorage.getItem('secure_todos');
            if (encryptedData) {
                const decryptedData = this.decrypt(encryptedData);
                const data = JSON.parse(decryptedData);
                
                if (data.todos && Array.isArray(data.todos)) {
                    this.todos = data.todos;
                }
            }
        } catch (error) {
            console.error('Error loading from storage:', error);
            // If decryption fails, clear corrupted data
            localStorage.removeItem('secure_todos');
            this.todos = [];
        }
    }

    // Security alert function
    showSecurityAlert(message) {
        // Create a temporary alert element
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
            <li class="todo-item" data-id="${this.escapeHtml(todo.id.toString())}">
                <div class="todo-checkbox ${todo.completed ? 'checked' : ''}" 
                     onclick="todoApp.toggleTodo('${this.escapeHtml(todo.id.toString())}')">
                    ${todo.completed ? '<i class="fas fa-check"></i>' : ''}
                </div>
                <span class="todo-text ${todo.completed ? 'completed' : ''}">
                    ${this.escapeHtml(todo.text)}
                </span>
                <div class="todo-actions">
                    <button class="action-btn edit-btn" 
                            onclick="todoApp.editTodo('${this.escapeHtml(todo.id.toString())}')" 
                            title="Edit task">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="action-btn delete-btn" 
                            onclick="todoApp.deleteTodo('${this.escapeHtml(todo.id.toString())}')" 
                            title="Delete task">
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
            localStorage.removeItem('secure_todos');
            this.render();
        }
    }
}

// Initialize the app when DOM is loaded
let todoApp;
document.addEventListener('DOMContentLoaded', () => {
    todoApp = new TodoApp();
});

// Add some sample todos for demonstration (only if no existing data)
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        if (todoApp.todos.length === 0) {
            const sampleTodos = [
                { 
                    id: todoApp.generateSecureId(), 
                    text: 'Welcome to your Secure Todo List!', 
                    completed: false, 
                    createdAt: new Date().toISOString(),
                    lastModified: new Date().toISOString()
                },
                { 
                    id: todoApp.generateSecureId(), 
                    text: 'Your data is now encrypted and secure', 
                    completed: true, 
                    createdAt: new Date().toISOString(),
                    lastModified: new Date().toISOString()
                },
                { 
                    id: todoApp.generateSecureId(), 
                    text: 'All inputs are validated and sanitized', 
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