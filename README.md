# Rapido Corporate Backend API - Optimized

A comprehensive, production-ready backend API for the Rapido Corporate Ride Booking System with full Swagger documentation, validation, security, and optimized code structure.

## 🚀 Features

### Core Features
- **User Authentication & Authorization** with JWT tokens
- **Role-based Access Control** (User/Admin)
- **Ride Booking & Management** with approval workflow
- **Admin Dashboard** for ride approval and user management
- **Password Reset** functionality
- **Profile Management** for users

### Technical Features
- **Swagger/OpenAPI 3.0** documentation with interactive UI
- **Comprehensive Input Validation** using express-validator
- **Security Middleware** (Helmet, CORS, Rate Limiting)
- **Error Handling** with custom error responses
- **MongoDB Integration** with Mongoose ODM
- **Environment-based Configuration**
- **Logging & Monitoring**
- **API Versioning** ready

## 📋 Prerequisites

- Node.js >= 14.0.0
- MongoDB (local or Atlas)
- npm or yarn

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend-api
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   ```bash
   # Copy the example environment file
   cp env.example .env
   
   # Edit .env with your configuration
   nano .env
   ```

4. **Database Setup**
   - Create a MongoDB database (local or Atlas)
   - Update `MONGODB_URI` in your `.env` file
   - See `DATABASE_SETUP.md` for detailed instructions

5. **Start the server**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

## 🔧 Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
NODE_ENV=development
PORT=5000

# MongoDB Configuration
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/rapido_db?retryWrites=true&w=majority

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here-make-it-long-and-random
JWT_EXPIRE=30d
JWT_COOKIE_EXPIRE=30

# Security
BCRYPT_SALT_ROUNDS=12

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS Configuration
CORS_ORIGIN=http://localhost:3000,http://localhost:5173,http://localhost:8080
```

## 📚 API Documentation

### Interactive Swagger UI
- **URL**: `http://localhost:5000/api-docs`
- **Features**: 
  - Interactive API testing
  - Request/Response examples
  - Authentication support
  - Schema validation

### API Endpoints Overview

#### Authentication (`/api/auth`)
- `POST /register` - User registration
- `POST /login` - User login
- `GET /me` - Get current user profile
- `PUT /profile` - Update user profile
- `PUT /change-password` - Change password
- `POST /logout` - User logout
- `POST /forgot-password` - Request password reset
- `PUT /reset-password/:token` - Reset password
- `POST /refresh` - Refresh access token

#### Rides (`/api/rides`)
- `GET /` - Get user's rides (with filtering)
- `POST /` - Create new ride request
- `GET /:id` - Get specific ride details
- `PUT /:id` - Update ride (pending only)
- `DELETE /:id` - Cancel ride

#### Admin (`/api/admin`)
- `GET /rides` - Get all rides (admin only)
- `PUT /rides/:id/status` - Update ride status
- `GET /users` - Get all users (admin only)
- `PUT /users/:id` - Update user (admin only)
- `GET /analytics` - Get analytics data

#### Users (`/api/users`)
- `GET /` - Get all users (admin only)
- `GET /:id` - Get specific user (admin only)
- `PUT /:id` - Update user (admin only)

## 🔐 Security Features

### Authentication
- JWT-based authentication
- Password hashing with bcrypt
- Token expiration and refresh
- Secure cookie handling

### Authorization
- Role-based access control
- Route protection middleware
- Admin-only endpoints

### Input Validation
- Comprehensive request validation
- SQL injection prevention
- XSS protection
- Input sanitization

### Security Headers
- Helmet.js for security headers
- CORS configuration
- Rate limiting
- Request size limits

## 🏗️ Project Structure

```
backend-api/
├── src/
│   ├── config/
│   │   ├── swagger.js          # Swagger configuration
│   │   └── swaggerUI.js        # Swagger UI styling
│   ├── controllers/
│   │   ├── authController.js   # Authentication logic
│   │   ├── rideController.js   # Ride management
│   │   ├── userController.js   # User management
│   │   └── adminController.js  # Admin operations
│   ├── middleware/
│   │   ├── auth.js             # Authentication middleware
│   │   ├── validation.js       # Input validation
│   │   ├── errorHandler.js     # Error handling
│   │   └── database.js         # Database error handling
│   ├── models/
│   │   ├── User.js             # User schema
│   │   ├── Ride.js             # Ride schema
│   │   └── AdminAction.js      # Admin actions schema
│   ├── routes/
│   │   ├── auth.js             # Auth routes
│   │   ├── rides.js            # Ride routes
│   │   ├── users.js            # User routes
│   │   └── admin.js            # Admin routes
│   └── utils/
│       ├── auth.js             # Auth utilities
│       └── database.js         # Database connection
├── app.js                      # Main application file
├── package.json
├── env.example                 # Environment variables example
└── README_OPTIMIZED.md         # This file
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run specific test file
npm test -- --testPathPattern=auth
```

### Test Coverage
```bash
npm run test:coverage
```

## 📊 Database Schema

### User Model
```javascript
{
  firstName: String (required),
  lastName: String (required),
  email: String (required, unique),
  password: String (required, hashed),
  phone: String (required),
  employeeId: String (required, unique),
  department: String (required, enum),
  role: String (enum: ['user', 'admin']),
  isActive: Boolean (default: true),
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  lastLoginAt: Date,
  loginAttempts: Number,
  lockUntil: Date
}
```

### Ride Model
```javascript
{
  userId: ObjectId (ref: 'User'),
  pickup: {
    address: String (required),
    latitude: Number,
    longitude: Number,
    landmark: String
  },
  drop: {
    address: String (required),
    latitude: Number,
    longitude: Number,
    landmark: String
  },
  scheduleTime: Date (required),
  status: String (enum),
  estimatedFare: Number,
  actualFare: Number,
  purpose: String,
  specialRequirements: String,
  driver: {
    name: String,
    phone: String,
    vehicle: String,
    rating: Number
  },
  approvedBy: ObjectId (ref: 'User'),
  approvedAt: Date,
  rejectedBy: ObjectId (ref: 'User'),
  rejectedAt: Date,
  rejectionReason: String,
  cancelledAt: Date,
  cancellationReason: String,
  feedback: {
    rating: Number,
    comment: String
  }
}
```

## 🚀 Deployment

### Production Checklist
- [ ] Set `NODE_ENV=production`
- [ ] Configure secure MongoDB connection
- [ ] Set strong JWT secret
- [ ] Configure CORS for production domains
- [ ] Set up SSL/TLS certificates
- [ ] Configure logging and monitoring
- [ ] Set up backup strategy
- [ ] Configure rate limiting for production

### Docker Deployment
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["npm", "start"]
```

## 🔍 Monitoring & Logging

### Health Check
- **Endpoint**: `GET /health`
- **Response**: Server status, database connection, API version

### Logging
- Request logging with timestamps
- Error logging with stack traces
- Database connection logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Ensure all tests pass
6. Submit a pull request

## 📝 License

This project is licensed under the ISC License.

## 🆘 Support

For support and questions:
- Check the API documentation at `/api-docs`
- Review the health check at `/health`
- Check the logs for error details
- Contact the development team

## 🔄 Changelog

### v1.0.0 (Current)
- ✅ Complete authentication system
- ✅ Ride booking and management
- ✅ Rapido Captain Confirmation
- ✅ Minimum Ride ₹80/- Inr Confirmed
- ✅ Admin dashboard
- ✅ Swagger documentation
- ✅ Input validation
- ✅ Security middleware
- ✅ Error handling
- ✅ Database optimization
- ✅ Environment configuration
- ✅ Production readiness 