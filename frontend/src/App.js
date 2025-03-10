import React, { useState, useEffect } from 'react';
import { GoogleLogin } from 'react-google-login';

function App() {
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [token, setToken] = useState('');
    const [refreshToken, setRefreshToken] = useState('');
    const [csrfToken, setCsrfToken] = useState('');

    // Refresh token handler
    const refreshAccessToken = async () => {
        try {
            const response = await fetch('https://school.aiservers.com.br/api/refresh', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ refreshToken })
            });

            if (response.ok) {
                const { accessToken, newRefreshToken } = await response.json();
                setToken(accessToken);
                setRefreshToken(newRefreshToken);
                return accessToken;
            } else {
                handleLogout();
                return null;
            }
        } catch (error) {
            handleLogout();
            return null;
        }
    };

    const handleLogout = () => {
        setIsAuthenticated(false);
        setToken('');
        setRefreshToken('');
        setCsrfToken('');
        localStorage.clear();
        sessionStorage.clear();
    };

    const handleSendMessage = async () => {
        if (!input.trim() || !isAuthenticated) return;

        try {
            const response = await fetch(`${process.env.REACT_APP_API_URL}/webhook`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentToken}`,
                    'X-CSRF-Token': csrfToken,
                    'X-Request-ID': crypto.randomUUID()
                },
                credentials: 'include',
                body: JSON.stringify({
                    message: sanitizeInput(input),
                    conversationId: messages.length === 0 ? null : messages[0].conversationId,
                    timestamp: new Date().toISOString()
                })
            });

            if (response.status === 403) {
                await getCsrfToken();
                throw new Error('CSRF token expired');
            }

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            
            // Add AI response to chat
            const aiMessage = { role: 'assistant', content: data.message };
            setMessages(prev => [...prev, aiMessage]);

        } catch (error) {
            if (error.message === 'CSRF token expired') {
                handleSendMessage(); // Retry with new CSRF token
                return;
            }
            console.error('Error:', error);
            // Add error message to chat
            const errorMessage = { 
                role: 'system', 
                content: 'Sorry, there was an error processing your request.' 
            };
            setMessages(prev => [...prev, errorMessage]);
        }
    };

    const handleGoogleSuccess = async (response) => {
        try {
            const { tokenId } = response;
            const authResponse = await fetch('https://school.aiservers.com.br/api/auth/google', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ tokenId })
            });

            if (authResponse.ok) {
                const { accessToken, refreshToken: newRefreshToken, csrfToken: newCsrfToken } = await authResponse.json();
                setToken(accessToken);
                setRefreshToken(newRefreshToken);
                setCsrfToken(newCsrfToken);
                setIsAuthenticated(true);

                // Store tokens securely
                sessionStorage.setItem('csrfToken', newCsrfToken);
                localStorage.setItem('refreshToken', newRefreshToken);
            }
        } catch (error) {
            console.error('Authentication failed:', error);
        }
    };

    // Utility functions
    const isTokenExpired = (token) => {
        if (!token) return true;
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            return payload.exp * 1000 < Date.now();
        } catch {
            return true;
        }
    };

    const sanitizeInput = (input) => {
        return input.trim()
            .replace(/[<>]/g, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '');
    };

    const getCsrfToken = async () => {
        try {
            const response = await fetch('https://school.aiservers.com.br/api/csrf-token', {
                credentials: 'include'
            });
            if (response.ok) {
                const { csrfToken: newToken } = await response.json();
                setCsrfToken(newToken);
                sessionStorage.setItem('csrfToken', newToken);
            }
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
        }
    };

    // Initialize security tokens
    useEffect(() => {
        const savedRefreshToken = localStorage.getItem('refreshToken');
        const savedCsrfToken = sessionStorage.getItem('csrfToken');

        if (savedRefreshToken && savedCsrfToken) {
            setRefreshToken(savedRefreshToken);
            setCsrfToken(savedCsrfToken);
            refreshAccessToken();
        } else {
            getCsrfToken();
        }

        // Refresh CSRF token periodically
        const csrfInterval = setInterval(getCsrfToken, 3600000); // Every hour
        return () => clearInterval(csrfInterval);
    }, []);

    // Handle enter key press
    const handleKeyPress = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSendMessage();
        }
    };

    // Load auth token on component mount
    useEffect(() => {
        const savedToken = localStorage.getItem('authToken');
        if (savedToken) {
            setToken(savedToken);
            setIsAuthenticated(true);
        }
    }, []);

    return (
        <div className="app">
            {!isAuthenticated ? (
                <GoogleLogin
                    clientId={process.env.REACT_APP_GOOGLE_CLIENT_ID}
                    onSuccess={handleGoogleSuccess}
                    onFailure={(err) => console.log(err)}
                />
            ) : (
                <div className="chat-container">
                    <div className="messages">
                        {messages.map((msg, index) => (
                            <div key={index} className={`message ${msg.role}`}>
                                {msg.content}
                            </div>
                        ))}
                    </div>
                    <div className="input-container">
                        <textarea
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyPress={handleKeyPress}
                            placeholder="Type your message..."
                            rows="1"
                        />
                        <button onClick={handleSendMessage}>Send</button>
                    </div>
                </div>
            )}
        </div>
    );
}

export default App;