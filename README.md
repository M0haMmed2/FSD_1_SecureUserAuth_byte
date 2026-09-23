# Secure User Authentication API (`FSD_1_SecureUserAuth_byte`)

A full-stack authentication system built for the **Arithmatrix Virtual Internship Program (AVIP 2026)**.

## Tech Stack
* **Backend:** Python (FastAPI), PyJWT, Passlib (bcrypt) / Hashlib, Uvicorn
* **Frontend:** HTML5, CSS3, JavaScript (Fetch API)

## Security Features
* Password hashing before database storage
* JSON Web Token (JWT) generation upon valid login
* Protected endpoints verifying `Authorization: Bearer <token>` headers

## API Endpoints
* `POST /api/register` - Register a new user (`{"username": "...", "password": "..."}`)
* `POST /api/login` - Authenticate and receive a JWT token
* `GET /api/protected` - Secured endpoint accessible only with a valid JWT