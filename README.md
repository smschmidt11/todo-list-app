# Todo List Application

A modern, responsive to-do list application with full CRUD (Create, Read, Update, Delete) functionality built with vanilla HTML, CSS, and JavaScript.

## Features

### ✨ Core CRUD Operations
- **Create**: Add new tasks with a clean input interface
- **Read**: View all tasks with filtering options (All, Active, Completed)
- **Update**: Edit task text and toggle completion status
- **Delete**: Remove individual tasks or clear all completed tasks

### 🎨 Modern UI/UX
- Beautiful gradient background and modern design
- Smooth animations and hover effects
- Responsive design that works on all devices
- Font Awesome icons for better visual experience
- Modal dialog for editing tasks

### 🔧 Advanced Features
- **Local Storage**: Tasks persist between browser sessions
- **Filtering**: View all, active, or completed tasks
- **Task Counter**: Shows remaining active tasks
- **Empty State**: Friendly message when no tasks exist
- **Keyboard Support**: Use Enter key to add/edit tasks
- **Confirmation Dialogs**: Prevents accidental deletions

### 📱 Responsive Design
- Mobile-friendly interface
- Touch-optimized buttons and interactions
- Adaptive layout for different screen sizes

## Getting Started

### Prerequisites
- A modern web browser (Chrome, Firefox, Safari, Edge)
- No additional dependencies required

### Installation
1. Clone or download this repository
2. Open `index.html` in your web browser
3. Start managing your tasks!

### Usage

#### Adding Tasks
1. Type your task in the input field
2. Press Enter or click the "Add" button
3. Your task will appear at the top of the list

#### Managing Tasks
- **Complete a task**: Click the circular checkbox next to the task
- **Edit a task**: Click the edit (pencil) icon
- **Delete a task**: Click the trash icon
- **Filter tasks**: Use the filter buttons (All, Active, Completed)
- **Clear completed**: Click "Clear Completed" to remove all finished tasks

#### Keyboard Shortcuts
- **Enter**: Add new task or save edited task
- **Escape**: Close edit modal

## File Structure

```
todo-list/
├── index.html          # Main HTML structure
├── styles.css          # CSS styling and animations
├── script.js           # JavaScript functionality
└── README.md           # This file
```

## Technical Details

### Technologies Used
- **HTML5**: Semantic markup and structure
- **CSS3**: Modern styling with Flexbox, Grid, and animations
- **Vanilla JavaScript**: ES6+ features and modern DOM manipulation
- **Local Storage API**: Data persistence
- **Font Awesome**: Icons

### Browser Support
- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+

### Performance Features
- Efficient DOM manipulation
- Debounced input handling
- Optimized rendering with minimal reflows
- Local storage for data persistence

## Customization

### Styling
You can easily customize the appearance by modifying `styles.css`:
- Change colors in the CSS custom properties
- Modify the gradient background
- Adjust spacing and typography
- Add new animations

### Functionality
Extend the application by modifying `script.js`:
- Add due dates to tasks
- Implement task categories/tags
- Add priority levels
- Include task descriptions
- Add search functionality

## Contributing

Feel free to fork this project and submit pull requests for improvements!

## License

This project is open source and available under the [MIT License](LICENSE).

## Acknowledgments

- Font Awesome for the beautiful icons
- Modern CSS techniques for responsive design
- Local Storage API for data persistence 
