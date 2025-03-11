const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Database connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'https://school.aiservers.com.br',
    credentials: true
}));

// CSRF protection
const csrfProtection = csrf({
    cookie: {
        secure: true,
        sameSite: 'strict'
    }
});

// Token generation
const generateTokens = (userId) => {
    const accessToken = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
    return { accessToken, refreshToken };
};

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Google Auth endpoint
app.post('/api/auth/google', async (req, res) => {
    try {
        const { tokenId } = req.body;
        const ticket = await googleClient.verifyIdToken({
            idToken: tokenId,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const { email, sub: googleId } = ticket.getPayload();
        
        // Store or retrieve user from database
        const userResult = await pool.query(
            'INSERT INTO users (email, google_id) VALUES ($1, $2) ON CONFLICT (google_id) DO UPDATE SET email = $1 RETURNING id',
            [email, googleId]
        );
        
        const userId = userResult.rows[0].id;
        const { accessToken, refreshToken } = generateTokens(userId);

        // Store refresh token in database
        await pool.query(
            'UPDATE users SET refresh_token = $1 WHERE id = $2',
            [refreshToken, userId]
        );

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.json({ accessToken });
    } catch (error) {
        console.error('Auth error:', error);
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// Refresh token endpoint
app.post('/api/refresh', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const userResult = await pool.query(
            'SELECT * FROM users WHERE id = $1 AND refresh_token = $2',
            [decoded.userId, refreshToken]
        );

        if (userResult.rows.length === 0) return res.sendStatus(403);

        const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.userId);

        await pool.query(
            'UPDATE users SET refresh_token = $1 WHERE id = $2',
            [newRefreshToken, decoded.userId]
        );

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ accessToken });
    } catch (error) {
        res.sendStatus(403);
    }
});

// CSRF token endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Webhook endpoint with all security measures
app.post('/api/webhook', authenticateToken, csrfProtection, async (req, res) => {
    const { message, conversationId } = req.body;
    const userId = req.user.userId;

    try {
        // Store conversation if new
        let currentConversationId = conversationId;
        if (!conversationId) {
            const convResult = await pool.query(
                'INSERT INTO conversations (user_id) VALUES ($1) RETURNING id',
                [userId]
            );
            currentConversationId = convResult.rows[0].id;
        }

        // Store user message
        await pool.query(
            'INSERT INTO messages (conversation_id, content, role) VALUES ($1, $2, $3)',
            [currentConversationId, message, 'user']
        );

        // Forward to N8N webhook
        const n8nResponse = await fetch(process.env.N8N_WEBHOOK_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.N8N_AUTH_TOKEN}`
            },
            body: JSON.stringify({
                message,
                conversationId: currentConversationId,
                userId
            })
        });

        if (!n8nResponse.ok) {
            throw new Error('N8N webhook failed');
        }

        const aiResponse = await n8nResponse.json();

        // Store AI response
        await pool.query(
            'INSERT INTO messages (conversation_id, content, role) VALUES ($1, $2, $3)',
            [currentConversationId, aiResponse.message, 'assistant']
        );

        res.json({
            message: aiResponse.message,
            conversationId: currentConversationId
        });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'UPDATE users SET refresh_token = NULL WHERE id = $1',
            [req.user.userId]
        );
        res.clearCookie('refreshToken');
        res.sendStatus(200);
    } catch (error) {
        res.sendStatus(500);
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Add this near your other routes
app.get('/health', (req, res) => {
  // Check database connection
  pool.query('SELECT 1')
    .then(() => {
      res.status(200).json({ status: 'ok' });
    })
    .catch(err => {
      console.error('Health check failed:', err);
      res.status(500).json({ status: 'error', message: 'Database connection failed' });
    });
});