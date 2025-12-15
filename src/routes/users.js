const express = require('express');
const {
  getAllUsers,
  createUser,
  getUser,
  updateUser,
  deleteUser,
  deleteOwnAccount
} = require('../controllers/userController');
const { protect, authorize } = require('../middleware/auth');

const router = express.Router();

// Route for users to delete their own account (no admin required)
router.delete('/delete-account', protect, deleteOwnAccount);

// All user management routes require admin authentication
router.use(protect);
router.use(authorize('admin'));

/**
 * @swagger
 * /api/users:
 *   get:
 *     tags: [User Management]
 *     summary: Get all users (Admin only)
 *     description: Retrieve all active users in the system
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     count:
 *                       type: number
 *                       example: 25
 *                     data:
 *                       type: object
 *                       properties:
 *                         users:
 *                           type: array
 *                           items:
 *                             $ref: '#/components/schemas/User'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *   post:
 *     tags: [User Management]
 *     summary: Create new user (Admin only)
 *     description: Create a new user account in the system
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserRegistration'
 *           example:
 *             firstName: "Alice"
 *             lastName: "Johnson"
 *             email: "alice.johnson@company.com"
 *             password: "TempPass123!"
 *             phone: "+91-9876543212"
 *             employeeId: "EMP025"
 *             department: "Finance"
 *             role: "employee"
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         user:
 *                           $ref: '#/components/schemas/User'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router
  .route('/')
  .get(getAllUsers)
  .post(createUser);

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     tags: [User Management]
 *     summary: Get user by ID (Admin only)
 *     description: Retrieve detailed information about a specific user
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *         example: "60d5ecb74d8b8e001c8e4b1a"
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         user:
 *                           $ref: '#/components/schemas/User'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *   put:
 *     tags: [User Management]
 *     summary: Update user (Admin only)
 *     description: Update user information (password cannot be updated via this endpoint)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *         example: "60d5ecb74d8b8e001c8e4b1a"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *                 example: "John"
 *               lastName:
 *                 type: string
 *                 example: "Smith"
 *               email:
 *                 type: string
 *                 format: email
 *                 example: "john.smith@company.com"
 *               phone:
 *                 type: string
 *                 example: "+91-9876543210"
 *               department:
 *                 type: string
 *                 example: "Marketing"
 *               role:
 *                 type: string
 *                 enum: [employee, admin]
 *                 example: "employee"
 *               isActive:
 *                 type: boolean
 *                 example: true
 *           example:
 *             firstName: "John"
 *             lastName: "Smith"
 *             department: "Marketing"
 *             role: "admin"
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         user:
 *                           $ref: '#/components/schemas/User'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *   delete:
 *     tags: [User Management]
 *     summary: Deactivate user (Admin only)
 *     description: Soft delete a user by setting isActive to false
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *         example: "60d5ecb74d8b8e001c8e4b1a"
 *     responses:
 *       200:
 *         description: User deactivated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiResponse'
 *             example:
 *               success: true
 *               message: "User deactivated successfully"
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router
  .route('/:id')
  .get(getUser)
  .put(updateUser)
  .delete(deleteUser);

module.exports = router;
