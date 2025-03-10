# AIServers School Helper

A web-based interface for the AIServers School Helper, providing students with an AI-powered learning assistant.

## Features

- Chat interface similar to ChatGPT
- Google OAuth2 authentication
- Conversation history storage
- Secure communication with N8N webhook
- Docker Swarm deployment
- CSRF protection
- Secure token management
- Rate limiting
- Security logging

## Project Structure

```plaintext
.
├── frontend/
│   ├── src/
│   │   └── App.js
│   ├── public/
│   │   ├── index.html
│   │   └── styles.css
│   ├── .env
│   └── Dockerfile
├── backend/
│   ├── src/
│   │   └── server.js
│   ├── .env
│   └── Dockerfile
├── database/
│   ├── init.sql
│   └── Dockerfile
└── docker-compose.yml


## Environment Setup

### Frontend Environment Variables
- REACT_APP_GOOGLE_CLIENT_ID: Google OAuth client ID
- REACT_APP_API_URL: Backend API URL


### Backend Environment Variables
- DB_USER: Database username
- DB_HOST: Database host
- DB_NAME: Database name
- DB_PASSWORD: Database password
- DB_PORT: Database port
- JWT_SECRET: JWT signing secret
- REFRESH_TOKEN_SECRET: Refresh token secret
- GOOGLE_CLIENT_ID: Google OAuth client ID
- N8N_WEBHOOK_URL: N8N webhook URL
- N8N_AUTH_TOKEN: N8N authentication token


## Security Features
- Google OAuth2 Authentication
- JWT Token Authentication
- CSRF Protection
- Refresh Token Mechanism
- Rate Limiting
- Security Logging
- Secure Cookie Handling
- Input Sanitization


## API Endpoints
- /api/auth/google : Google authentication
- /api/refresh : Token refresh
- /api/csrf-token : CSRF token generation
- /api/webhook : Message handling
- /api/logout : User logout


## Deployment
The application is designed to run in a Docker Swarm environment with Traefik as the reverse proxy. The domain is configured as school.aiservers.com.br .


### Prerequisites
- Docker Swarm cluster
- Traefik configured as reverse proxy
- PostgreSQL database
- Google OAuth credentials
- N8N instance with webhook configuration


### Installation
1. Clone the repository
2. Configure environment variables
3. Deploy using Docker Swarm:
```bash
docker stack deploy -c docker-compose.yml schoolhelper
 ```
```

## Database Schema
### Tables
- users: User information and authentication
- conversations: Chat conversation records
- messages: Individual message storage
- security_logs: Security event logging
