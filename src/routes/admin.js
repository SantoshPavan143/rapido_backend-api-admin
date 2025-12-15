const express = require('express');
const {
  getAllRides,
  approveRide,
  rejectRide,
  getRideAnalytics,
  getAdminActions,
  getRecentActivity
} = require('../controllers/adminController');
const { protect, authorize } = require('../middleware/auth');

const router = express.Router();

// All admin routes require admin authentication
router.use(protect);
router.use(authorize('admin'));

/**
 * @swagger
 * /api/admin/rides:
 *   get:
 *     tags: [Admin]
 *     summary: Get all rides (Admin only)
 *     description: Retrieve all rides in the system with advanced filtering and pagination
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [pending, approved, rejected, in-progress, completed, cancelled]
 *         description: Filter rides by status
 *         example: pending
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *         description: Filter rides by user ID
 *         example: "60d5ecb74d8b8e001c8e4b1a"
 *       - in: query
 *         name: department
 *         schema:
 *           type: string
 *           enum: [Engineering, HR, Finance, Marketing, Operations, Sales, Other]
 *         description: Filter rides by user department
 *         example: Engineering
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter rides from this date
 *         example: "2024-01-01"
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter rides until this date
 *         example: "2024-01-31"
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number for pagination
 *         example: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 10
 *         description: Number of items per page
 *         example: 10
 *     responses:
 *       200:
 *         description: Rides retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PaginatedResponse'
 *             example:
 *               success: true
 *               count: 10
 *               total: 125
 *               pagination:
 *                 page: 1
 *                 limit: 10
 *                 totalPages: 13
 *               data:
 *                 rides:
 *                   - _id: "60d5ecb74d8b8e001c8e4b1b"
 *                     userId:
 *                       _id: "60d5ecb74d8b8e001c8e4b1a"
 *                       firstName: "John"
 *                       lastName: "Doe"
 *                       department: "Engineering"
 *                     status: "pending"
 *                     estimatedFare: 250
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router.get('/rides', getAllRides);

/**
 * @swagger
 * /api/admin/rides/{id}/approve:
 *   put:
 *     tags: [Admin]
 *     summary: Approve ride request (Admin only)
 *     description: Approve a pending ride request with optional comments
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Ride ID to approve
 *         example: "60d5ecb74d8b8e001c8e4b1b"
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               comments:
 *                 type: string
 *                 description: Optional approval comments
 *                 example: "Approved for business meeting"
 *           example:
 *             comments: "Approved for business meeting"
 *     responses:
 *       200:
 *         description: Ride approved successfully
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
 *                         ride:
 *                           $ref: '#/components/schemas/Ride'
 *             example:
 *               success: true
 *               message: "Ride approved successfully"
 *               data:
 *                 ride:
 *                   _id: "60d5ecb74d8b8e001c8e4b1b"
 *                   status: "approved"
 *                   approvedBy: "60d5ecb74d8b8e001c8e4b1c"
 *                   adminComments: "Approved for business meeting"
 *       400:
 *         description: Can only approve pending rides
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               success: false
 *               message: "Can only approve pending rides"
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router.put('/rides/:id/approve', approveRide);

/**
 * @swagger
 * /api/admin/rides/{id}/reject:
 *   put:
 *     tags: [Admin]
 *     summary: Reject ride request (Admin only)
 *     description: Reject a pending ride request with reason and optional comments
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Ride ID to reject
 *         example: "60d5ecb74d8b8e001c8e4b1b"
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reason:
 *                 type: string
 *                 description: Reason for rejection
 *                 example: "Budget constraints for this month"
 *               comments:
 *                 type: string
 *                 description: Optional rejection comments
 *                 example: "Please use public transport"
 *           example:
 *             reason: "Budget constraints for this month"
 *             comments: "Please use public transport"
 *     responses:
 *       200:
 *         description: Ride rejected successfully
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
 *                         ride:
 *                           $ref: '#/components/schemas/Ride'
 *             example:
 *               success: true
 *               message: "Ride rejected successfully"
 *               data:
 *                 ride:
 *                   _id: "60d5ecb74d8b8e001c8e4b1b"
 *                   status: "rejected"
 *                   rejectedBy: "60d5ecb74d8b8e001c8e4b1c"
 *                   rejectionReason: "Budget constraints for this month"
 *       400:
 *         description: Can only reject pending rides
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               success: false
 *               message: "Can only reject pending rides"
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router.put('/rides/:id/reject', rejectRide);

/**
 * @swagger
 * /api/admin/analytics:
 *   get:
 *     tags: [Admin]
 *     summary: Get ride analytics (Admin only)
 *     description: Retrieve comprehensive analytics and reports for rides
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter analytics from this date
 *         example: "2024-01-01"
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter analytics until this date
 *         example: "2024-01-31"
 *       - in: query
 *         name: department
 *         schema:
 *           type: string
 *           enum: [Engineering, HR, Finance, Marketing, Operations, Sales, Other]
 *         description: Filter analytics by department
 *         example: Engineering
 *     responses:
 *       200:
 *         description: Analytics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/Analytics'
 *             example:
 *               success: true
 *               data:
 *                 summary:
 *                   totalRides: 1250
 *                   pendingRides: 45
 *                   approvedRides: 980
 *                   rejectedRides: 125
 *                   completedRides: 950
 *                   cancelledRides: 100
 *                   approvalRate: "78.40"
 *                 departmentAnalytics:
 *                   - _id: "Engineering"
 *                     totalRides: 450
 *                     totalFare: 112500
 *                     avgFare: 250
 *                   - _id: "Marketing"
 *                     totalRides: 300
 *                     totalFare: 75000
 *                     avgFare: 250
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router.get('/analytics', getRideAnalytics);

/**
 * @swagger
 * /api/admin/actions:
 *   get:
 *     tags: [Admin]
 *     summary: Get admin action logs (Admin only)
 *     description: Retrieve audit trail of all admin actions with pagination
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number for pagination
 *         example: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *         description: Number of actions per page
 *         example: 20
 *     responses:
 *       200:
 *         description: Admin actions retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/PaginatedResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         actions:
 *                           type: array
 *                           items:
 *                             $ref: '#/components/schemas/AdminAction'
 *             example:
 *               success: true
 *               count: 20
 *               total: 150
 *               pagination:
 *                 page: 1
 *                 limit: 20
 *                 totalPages: 8
 *               data:
 *                 actions:
 *                   - _id: "60d5ecb74d8b8e001c8e4b1d"
 *                     adminId:
 *                       firstName: "Jane"
 *                       lastName: "Smith"
 *                       email: "jane.smith@company.com"
 *                     action: "approve_ride"
 *                     targetType: "Ride"
 *                     targetId: "60d5ecb74d8b8e001c8e4b1b"
 *                     details:
 *                       rideId: "60d5ecb74d8b8e001c8e4b1b"
 *                       userId: "60d5ecb74d8b8e001c8e4b1a"
 *                       comments: "Approved for business meeting"
 *                     createdAt: "2024-01-15T10:30:00.000Z"
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router.get('/actions', getAdminActions);

/**
 * @swagger
 * /api/admin/recent-activity:
 *   get:
 *     tags: [Admin]
 *     summary: Get recent activity for dashboard
 *     description: Retrieve recent activities including ride updates and admin actions
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 10
 *         description: Maximum number of activities to return
 *     responses:
 *       200:
 *         description: Recent activity retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     activities:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           id:
 *                             type: string
 *                           type:
 *                             type: string
 *                           description:
 *                             type: string
 *                           icon:
 *                             type: string
 *                           timestamp:
 *                             type: string
 *                             format: date-time
 *                           data:
 *                             type: object
 *                     total:
 *                       type: integer
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router.get('/recent-activity', getRecentActivity);

module.exports = router;
