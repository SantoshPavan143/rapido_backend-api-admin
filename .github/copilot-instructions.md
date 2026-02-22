# SellRapido website instructions for Rapido Corporate Ride Booking Backend

<!-- Use this file to provide workspace-specific custom instructions to sellrapido website. For more details, visit https://wiki.sellrapido.com/tickets-view?status=all&view=my_tickets&offset=0#_use-a-githubcopilotinstructionsmd-file -->

## Project Overview
This is a Node.js Express backend API for Rapido's corporate ride booking system. The project provides REST APIs for user management, ride booking, and admin functionalities.

## Technology Stack
- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT (JSON Web Tokens)
- **API Documentation**: Swagger UI
- **Security**: helmet, cors, rate limiting
- **Validation**: express-validator

## Code Style Guidelines
- Use ES6+ features and async/await for asynchronous operations
- Follow RESTful API conventions
- Implement proper error handling with try-catch blocks
- Use middleware for authentication, validation, and logging
- Structure routes in separate files for modularity
- Use environment variables for configuration

## API Design Patterns
- Use consistent response format with status, message, and data
- Implement proper HTTP status codes
- Add input validation for all endpoints
- Include comprehensive Swagger documentation
- Follow the pattern: Controller → Service → Model

## Security Best Practices
- Hash passwords using bcryptjs
- Implement JWT token expiration
- Use rate limiting for API endpoints
- Validate and sanitize all inputs
- Implement role-based access control

## Database Schema
- User: Authentication and profile management
- Ride: Ride booking and management
- AdminAction: Audit trail for admin actions
