# ThreatWeaver

 **Phase 1:  Foundation & Core Backend**     

- [ ]  Setup
- Initialize project structure (backend/, frontend2/)
- Set up Python virtual environment
- Configure .env with database, JWT, and LLM settings
- Initialize Git repository with proper .gitignore
- Set up PostgreSQL connection with SQLAlchemy

- [ ]  Backend Core
- FastAPI app with lifespan events (startup/shutdown)
- CORS middleware for frontend communication
- Request ID middleware for tracing
- Exception handlers for consistent error responses
- Health check endpoints (/health,  /test-db)

- [ ]  Authentication
- User model with password hashing (passlib/bcrypt)
- JWT token generation and validation
- Refresh token flow
- Auth router (register, login, refresh, logout)
- Dependency for protected routes

