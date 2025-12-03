// server.js

// Import necessary libraries
require('dotenv').config(); // Load environment variables
const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
// Import the MySQL session store
const MySQLStore = require('express-mysql-session')(session);

// Initialize the Express application
const app = express();
const port = process.env.PORT || 3000; // Use env port or default to 3000

// Set EJS as the view engine and set the directory for templates
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware to parse incoming form data and JSON requests
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ----------------------------------------------------
// Database & Session Configuration
// ----------------------------------------------------

// Define Database Options (Used for both DB connection and Session Store)
const dbOptions = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE || 'mining_project',
    // SSL is usually required for cloud databases like PlanetScale or Aiven
    ssl: { rejectUnauthorized: true } 
};

// Create the Database Connection
const db = mysql.createConnection(dbOptions);

db.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to MySQL database!');
});

// Configure Session Store (Stores sessions in MySQL instead of memory)
const sessionStore = new MySQLStore(dbOptions);

// Configure session middleware
app.use(session({
    key: 'session_cookie_name',
    secret: process.env.SESSION_SECRET || 'fallback_secret_key',
    store: sessionStore, // Use the MySQL store
    resave: false,
    saveUninitialized: false, // Set to false to save storage space
    cookie: { 
        // Secure should be true in production (HTTPS), false in local dev
        secure: process.env.NODE_ENV === 'production', 
        maxAge: 30 * 60 * 1000 // 30 minutes
    } 
}));

// ----------------------------------------------------
// Middleware for Authentication
// ----------------------------------------------------

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login.html');
    }
}

// ----------------------------------------------------
// Routes
// ----------------------------------------------------

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- Protected Routes ---

app.get('/form.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'form.html'));
});

app.post('/submit-form', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Unauthorized: Please log in.');
    }

    const formData = req.body;
    const userId = req.session.userId;

    const sql = `INSERT INTO handover_logs (
        date, time, outgoing_shift, outgoing_leader_first_name, outgoing_leader_last_name,
        emergency_equipment_status, hsse_incidents, permits_status, isolations_overrides_suppressions,
        reappraisal_needed, simops_issues, mocs_implemented, abnormal_operation_modes,
        changes_during_shift, changes_next_shift, equipment_availability_issues, personal_issues,
        general_communications, log_complete, briefing_leaders, briefing_workers, adequate_time,
        distraction_free_location, work_area_inspections, reappraisal_performed, leader_discussed_info,
        leader_signed_log, suggestions_for_improvement, incoming_shift, incoming_leader_first_name,
        incoming_leader_last_name, submitted_by_user_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    const values = [
        formData.date, formData.time, formData.outgoing_shift, formData.outgoing_leader_first_name,
        formData.outgoing_leader_last_name, formData.emergency_equipment_status, formData.hsse_incidents,
        formData.permits_status, formData.isolations_overrides_suppressions, formData.reappraisal_needed,
        formData.simops_issues, formData.mocs_implemented, formData.abnormal_operation_modes,
        formData.changes_during_shift, formData.changes_next_shift, formData.equipment_availability_issues,
        formData.personal_issues, formData.general_communications, formData.log_complete,
        formData.briefing_leaders, formData.briefing_workers, formData.adequate_time,
        formData.distraction_free_location, formData.work_area_inspections, formData.reappraisal_performed,
        formData.leader_discussed_info, formData.leader_signed_log, formData.suggestions_for_improvement,
        formData.incoming_shift, formData.incoming_leader_first_name, formData.incoming_leader_last_name,
        userId
    ];

    db.query(sql, values, (err, result) => {
        if (err) {
            console.error('Error inserting form data:', err);
            return res.status(500).send('Error submitting form data.');
        }
        res.redirect('/dashboard');
    });
});

app.post('/register', async (req, res) => {
    try {
        const { username, first_name, last_name, password, role } = req.body;

        const checkUserSql = `SELECT * FROM users WHERE username = ?`;
        db.query(checkUserSql, [username], async (err, results) => {
            if (err) {
                return res.status(500).send('Internal server error.');
            }
            if (results.length > 0) {
                return res.redirect('/signup.html?error=duplicate');
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const sql = `INSERT INTO users (username, first_name, last_name, password, role) VALUES (?, ?, ?, ?, ?)`;
            const values = [username, first_name, last_name, hashedPassword, role];

            db.query(sql, values, (err, result) => {
                if (err) {
                    return res.status(500).send('Error creating user.');
                }
                res.redirect('/login.html');
            });
        });
    } catch (error) {
        res.status(500).send('Internal server error.');
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = `SELECT * FROM users WHERE username = ?`;
    db.query(sql, [username], async (err, results) => {
        if (err || results.length === 0) {
            return res.redirect('/login.html?error=invalid');
        }
        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
            req.session.userId = user.id;
            req.session.role = user.role;
            res.redirect('/dashboard');
        } else {
            res.redirect('/login.html?error=invalid');
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        res.redirect('/login.html');
    });
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    const { search, date } = req.query;
    let sql = `SELECT * FROM handover_logs`;
    const queryParams = [];

    let whereClauses = [];

    if (req.session.role === 'manager') {
        // Manager sees all, filters apply
    } else {
        // Operator sees only their own
        whereClauses.push(`submitted_by_user_id = ?`);
        queryParams.push(req.session.userId);
    }

    if (search) {
        whereClauses.push(`(outgoing_shift LIKE ? OR outgoing_leader_first_name LIKE ? OR outgoing_leader_last_name LIKE ?)`);
        const searchTerm = `%${search}%`;
        queryParams.push(searchTerm, searchTerm, searchTerm);
    }
    if (date) {
        whereClauses.push(`date = ?`);
        queryParams.push(date);
    }

    if (whereClauses.length > 0) {
        sql += ` WHERE ` + whereClauses.join(' AND ');
    }

    sql += ` ORDER BY created_at DESC`;

    db.query(sql, queryParams, (err, results) => {
        if (err) {
            return res.status(500).send('Error retrieving logs.');
        }
        res.render('dashboard', { logs: results, role: req.session.role, search: search, date: date });
    });
});

app.get('/log/:id', isAuthenticated, (req, res) => {
    const logId = req.params.id;
    const sql = `SELECT * FROM handover_logs WHERE id = ?`;
    db.query(sql, [logId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send('Log not found.');
        }
        res.render('log_details', { log: results[0] });
    });
});

// --- Public Routes ---
app.use(express.static(path.join(__dirname)));

// ----------------------------------------------------
// Start the Server (Conditional for Vercel)
// ----------------------------------------------------

// Only run app.listen if running locally (not imported as a module)
if (require.main === module) {
    app.listen(port, () => {
        console.log(`Server is running at http://localhost:${port}`);
    });
}

// Export the app for Vercel Serverless Functions
module.exports = app;