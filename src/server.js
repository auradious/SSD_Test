import express from 'express';

const app = express();

// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Basic authentication middleware
const basicAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Restricted Area"');
        return res.status(401).send('Authentication required');
    }
    
    const credentials = Buffer.from(authHeader.slice(6), 'base64').toString().split(':');
    const username = credentials[0];
    const password = credentials[1];
    
    // Fixed to match docker-compose.yml environment variables
    const expectedUsername = process.env.AUTH_USERNAME || 'admin';
    const expectedPassword = process.env.AUTH_PASSWORD || '2301831@sit.singaporetech.edu.sg';
    
    if (username === expectedUsername && password === expectedPassword) {
        next();
    } else {
        res.setHeader('WWW-Authenticate', 'Basic realm="Restricted Area"');
        return res.status(401).send('Invalid credentials');
    }
};

// XSS Detection Function (OWASP Top 10 Proactive C5: Validate All Inputs)
const detectXSS = (input) => {
    if (!input || typeof input !== 'string') return false;
    
    // Common XSS patterns
    const xssPatterns = [
        /<script[^>]*>.*?<\/script>/gi,
        /<iframe[^>]*>.*?<\/iframe>/gi,
        /<object[^>]*>.*?<\/object>/gi,
        /<embed[^>]*>/gi,
        /<link[^>]*>/gi,
        /<meta[^>]*>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /onload\s*=/gi,
        /onerror\s*=/gi,
        /onclick\s*=/gi,
        /onmouseover\s*=/gi,
        /onfocus\s*=/gi,
        /onblur\s*=/gi,
        /onchange\s*=/gi,
        /onsubmit\s*=/gi,
        /<img[^>]*src\s*=\s*["']?javascript:/gi,
        /<svg[^>]*onload/gi,
        /expression\s*\(/gi,
        /@import/gi,
        /&lt;script/gi,
        /&lt;iframe/gi,
        /%3Cscript/gi,
        /%3Ciframe/gi
    ];
    
    return xssPatterns.some(pattern => pattern.test(input));
};

// SQL Injection Detection Function
const detectSQLInjection = (input) => {
    if (!input || typeof input !== 'string') return false;
    
    // Common SQL injection patterns
    const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/gi,
        /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
        /(\b(OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/gi,
        /(;|\||&)/g,
        /('|(\\')|('')|(\\")|(")|(\\""))/g,
        /(\/\*|\*\/|--|\#)/g,
        /(\b(WAITFOR|DELAY)\b)/gi,
        /(\b(CAST|CONVERT|ASCII|CHAR|SUBSTRING)\b)/gi,
        /(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b)/gi,
        /(0x[0-9A-F]+)/gi,
        /(\b(XP_|SP_)\w+)/gi,
        /(BENCHMARK\s*\()/gi,
        /(SLEEP\s*\()/gi,
        /(LOAD_FILE\s*\()/gi,
        /(INTO\s+OUTFILE)/gi
    ];
    
    return sqlPatterns.some(pattern => pattern.test(input));
};

// HTML Escape Function for safe output
const escapeHtml = (text) => {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
};

// Apply authentication to all routes
app.use(basicAuth);

// Home page with search form
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Search Portal</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    max-width: 800px; 
                    margin: 50px auto; 
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                .form-group {
                    margin: 20px 0;
                }
                input[type="text"] {
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #ddd;
                    border-radius: 5px;
                    font-size: 16px;
                    box-sizing: border-box;
                }
                button {
                    background: #007bff;
                    color: white;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 5px;
                    font-size: 16px;
                    cursor: pointer;
                }
                button:hover {
                    background: #0056b3;
                }
                .services {
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                }
                .error {
                    color: #dc3545;
                    margin: 10px 0;
                    padding: 10px;
                    background: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to the Protected Web App!</h1>
                <p>You are successfully authenticated as: <strong>${process.env.AUTH_USERNAME || 'admin'}</strong></p>
                
                <h2>Secure Search Portal</h2>
                <form method="POST" action="/search">
                    <div class="form-group">
                        <label for="searchTerm">Enter search term:</label>
                        <input type="text" id="searchTerm" name="searchTerm" placeholder="Enter your search term..." required>
                    </div>
                    <button type="submit">Search</button>
                </form>
                
                <div class="services">
                    <h3>Available services:</h3>
                    <ul>
                        <li><a href="http://localhost:9000" target="_blank">SonarQube</a> (admin/sonar123)</li>
                        <li><a href="http://localhost:3001" target="_blank">Gitea Git Server</a> (git123/git123)</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
    `);
});

// Handle search with security validation
app.post('/search', (req, res) => {
    const searchTerm = req.body.searchTerm || '';
    
    // Check for XSS attacks
    if (detectXSS(searchTerm)) {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Secure Search Portal</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        max-width: 800px; 
                        margin: 50px auto; 
                        padding: 20px;
                        background-color: #f5f5f5;
                    }
                    .container {
                        background: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }
                    .form-group {
                        margin: 20px 0;
                    }
                    input[type="text"] {
                        width: 100%;
                        padding: 12px;
                        border: 2px solid #ddd;
                        border-radius: 5px;
                        font-size: 16px;
                        box-sizing: border-box;
                    }
                    button {
                        background: #007bff;
                        color: white;
                        padding: 12px 24px;
                        border: none;
                        border-radius: 5px;
                        font-size: 16px;
                        cursor: pointer;
                    }
                    button:hover {
                        background: #0056b3;
                    }
                    .services {
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                    }
                    .error {
                        color: #dc3545;
                        margin: 10px 0;
                        padding: 10px;
                        background: #f8d7da;
                        border: 1px solid #f5c6cb;
                        border-radius: 5px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to the Protected Web App!</h1>
                    <p>You are successfully authenticated as: <strong>${process.env.AUTH_USERNAME || 'admin'}</strong></p>
                    
                    <div class="error">
                        <strong>⚠️ Security Alert:</strong> Potential XSS attack detected. Input has been cleared for security reasons.
                    </div>
                    
                    <h2>Secure Search Portal</h2>
                    <form method="POST" action="/search">
                        <div class="form-group">
                            <label for="searchTerm">Enter search term:</label>
                            <input type="text" id="searchTerm" name="searchTerm" placeholder="Enter your search term..." required>
                        </div>
                        <button type="submit">Search</button>
                    </form>
                    
                    <div class="services">
                        <h3>Available services:</h3>
                        <ul>
                            <li><a href="http://localhost:9000" target="_blank">SonarQube</a> (admin/sonar123)</li>
                            <li><a href="http://localhost:3001" target="_blank">Gitea Git Server</a> (git123/git123)</li>
                        </ul>
                    </div>
                </div>
            </body>
            </html>
        `);
        return;
    }
    
    // Check for SQL injection attacks
    if (detectSQLInjection(searchTerm)) {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Secure Search Portal</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        max-width: 800px; 
                        margin: 50px auto; 
                        padding: 20px;
                        background-color: #f5f5f5;
                    }
                    .container {
                        background: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }
                    .form-group {
                        margin: 20px 0;
                    }
                    input[type="text"] {
                        width: 100%;
                        padding: 12px;
                        border: 2px solid #ddd;
                        border-radius: 5px;
                        font-size: 16px;
                        box-sizing: border-box;
                    }
                    button {
                        background: #007bff;
                        color: white;
                        padding: 12px 24px;
                        border: none;
                        border-radius: 5px;
                        font-size: 16px;
                        cursor: pointer;
                    }
                    button:hover {
                        background: #0056b3;
                    }
                    .services {
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                    }
                    .error {
                        color: #dc3545;
                        margin: 10px 0;
                        padding: 10px;
                        background: #f8d7da;
                        border: 1px solid #f5c6cb;
                        border-radius: 5px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to the Protected Web App!</h1>
                    <p>You are successfully authenticated as: <strong>${process.env.AUTH_USERNAME || 'admin'}</strong></p>
                    
                    <div class="error">
                        <strong>⚠️ Security Alert:</strong> Potential SQL injection attack detected. Input has been cleared for security reasons.
                    </div>
                    
                    <h2>Secure Search Portal</h2>
                    <form method="POST" action="/search">
                        <div class="form-group">
                            <label for="searchTerm">Enter search term:</label>
                            <input type="text" id="searchTerm" name="searchTerm" placeholder="Enter your search term..." required>
                        </div>
                        <button type="submit">Search</button>
                    </form>
                    
                    <div class="services">
                        <h3>Available services:</h3>
                        <ul>
                            <li><a href="http://localhost:9000" target="_blank">SonarQube</a> (admin/sonar123)</li>
                            <li><a href="http://localhost:3001" target="_blank">Gitea Git Server</a> (git123/git123)</li>
                        </ul>
                    </div>
                </div>
            </body>
            </html>
        `);
        return;
    }
    
    // If validation passes, show search results
    const safeSearchTerm = escapeHtml(searchTerm);
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Search Results</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    max-width: 800px; 
                    margin: 50px auto; 
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                button {
                    background: #28a745;
                    color: white;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 5px;
                    font-size: 16px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                }
                button:hover {
                    background: #218838;
                }
                .search-result {
                    background: #d1edff;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                    border-left: 4px solid #007bff;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Search Results</h1>
                
                <div class="search-result">
                    <h3>Search Term Processed Successfully</h3>
                    <p><strong>Your search term:</strong> "${safeSearchTerm}"</p>
                    <p><strong>Status:</strong> ✅ Input validated and safe</p>
                    <p><strong>Timestamp:</strong> ${new Date().toLocaleString()}</p>
                </div>
                
                <a href="/" style="text-decoration: none;">
                    <button type="button">Return to Home Page</button>
                </a>
            </div>
        </body>
        </html>
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Authentication enabled - Username: ${process.env.AUTH_USERNAME || 'admin'}`);
});