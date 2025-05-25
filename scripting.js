// Add this at the beginning of script.js or after existing DOM content loaded scripts
const themeToggle = document.getElementById('theme-toggle');
const body = document.body; // Reference to the body element for class toggling

// Get saved theme preference from localStorage
const currentTheme = localStorage.getItem('theme');

// Function to apply the theme (light or dark)
function applyTheme(theme) {
    if (theme === 'dark') {
        body.classList.add('dark-theme');
        themeToggle.textContent = '🌙'; // Change icon to moon for dark theme
        themeToggle.setAttribute('aria-label', 'Switch to light theme');
    } else {
        body.classList.remove('dark-theme');
        themeToggle.textContent = '☀️'; // Change icon to sun for light theme
        themeToggle.setAttribute('aria-label', 'Switch to dark theme');
    }
}

// On page load, apply the saved theme or detect system preference
if (currentTheme) {
    applyTheme(currentTheme);
} else {
    // If no theme saved, check the user's system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        applyTheme('dark'); // Apply dark theme if system preference is dark
    } else {
        applyTheme('light'); // Default to light theme
    }
}

// Add event listener to the theme toggle button
themeToggle.addEventListener('click', () => {
    let themeToApply = 'light';
    // If body currently has 'dark-theme' class, switch to light
    if (body.classList.contains('dark-theme')) {
        themeToApply = 'light';
    } else {
        themeToApply = 'dark'; // Otherwise, switch to dark
    }
    applyTheme(themeToApply); // Apply the new theme
    localStorage.setItem('theme', themeToApply); // Save the preference for future visits
});

// --- Existing script.js code follows ---

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault(); // Prevent default anchor click behavior
        const target = document.querySelector(this.getAttribute('href')); // Get the target element
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth', // Smooth scroll animation
                block: 'start'      // Scroll to the start of the target element
            });
        }
    });
});

// Intersection Observer for scroll animations (fade-in effect)
const observerOptions = {
    threshold: 0.1, // Element is visible when 10% of it is in the viewport
    rootMargin: '0px 0px -50px 0px' // Shrink the bottom margin of the root to trigger earlier
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            // If the element is intersecting, add the 'visible' class to trigger animation
            entry.target.classList.add('visible');
        }
    });
}, observerOptions);

// Observe all elements with the 'fade-in' class
document.querySelectorAll('.fade-in').forEach(el => {
    observer.observe(el);
});

// Header background change on scroll
window.addEventListener('scroll', () => {
    const header = document.querySelector('header');
    // Using CSS variables for header background transition as well
    if (window.scrollY > 100) {
        header.style.background = 'var(--header-bg)'; // Will be dark if dark theme is active
        header.style.boxShadow = '0 2px 20px var(--header-shadow)';
    } else {
        header.style.background = 'var(--header-bg)';
        header.style.boxShadow = '0 2px 20px var(--header-shadow)';
    }
});


// --- Simplified Flowy Background Animation Logic ---

const canvas = document.getElementById('flowyBackground');
const ctx = canvas.getContext('2d');

// Mouse position object (only needs x, y now)
const mouse = {
    x: undefined,
    y: undefined
};

// Update mouse position on movement
window.addEventListener('mousemove', function(event) {
    mouse.x = event.x;
    mouse.y = event.y; // Corrected typo here (was event.x)
});

// Debounce the resize event to avoid performance spikes during resizing
let resizeTimer;
window.addEventListener('resize', function() {
    clearTimeout(resizeTimer); // Clear any existing timer
    resizeTimer = setTimeout(() => { // Set a new timer
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        // No particles to re-initialize here, just resizing the canvas
    }, 250); // Wait 250ms after resizing stops
});

// Main animation loop for the background gradient
function animateBackground() {
    requestAnimationFrame(animateBackground); // Request the next animation frame

    // Get current time for a subtle, continuous animation
    const time = Date.now() * 0.0005; // Scaled down time for smoother, slower movement

    // Define base animation for gradient start and end points
    // These points will oscillate smoothly over time
    let baseStartX = Math.sin(time * 0.5) * (canvas.width * 0.4) + canvas.width / 2;
    let baseStartY = Math.cos(time * 0.4) * (canvas.height * 0.4) + canvas.height / 2;
    let baseEndX = Math.cos(time * 0.3) * (canvas.width * 0.4) + canvas.width / 2;
    let baseEndY = Math.sin(time * 0.6) * (canvas.height * 0.4) + canvas.height / 2;

    // Define how strongly the mouse influences the gradient's movement
    const mouseInfluenceFactor = 0.2; // A value between 0 (no influence) and 1 (full follow)

    // Calculate final gradient points, blending the base animation with mouse position
    let finalStartX = baseStartX;
    let finalStartY = baseStartY;
    let finalEndX = baseEndX;
    let finalEndY = baseEndY;

    // If the mouse is on the screen, adjust the gradient points based on its position
    if (mouse.x !== undefined && mouse.y !== undefined) {
        // Linearly interpolate the start point towards the mouse position
        finalStartX = baseStartX * (1 - mouseInfluenceFactor) + mouse.x * mouseInfluenceFactor;
        finalStartY = baseStartY * (1 - mouseInfluenceFactor) + mouse.y * mouseInfluenceFactor;

        // For the end point, we can make it move towards a "mirrored" mouse position
        // This creates a nice stretch/pull effect as the mouse moves
        finalEndX = baseEndX * (1 - mouseInfluenceFactor) + (canvas.width - mouse.x) * mouseInfluenceFactor;
        finalEndY = baseEndY * (1 - mouseInfluenceFactor) + (canvas.height - mouse.y) * mouseInfluenceFactor;
    }

    // Create the linear gradient with our dynamically calculated points
    const gradient = ctx.createLinearGradient(finalStartX, finalStartY, finalEndX, finalEndY);
    gradient.addColorStop(0, '#667eea'); // Blue from original gradient
    gradient.addColorStop(1, '#764ba2'); // Lilac/Purple from original gradient
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height); // Fill the entire canvas with the gradient

    // IMPORTANT: No particles to update, and no computationally expensive blur filters.
    // This approach should be significantly more performant.
}

// Initial setup: Set canvas dimensions and start the animation loop
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
animateBackground(); // Start the animation loop