const express = require('express');
const {
  createRide,
  getUserRides,
  getRide,
  updateRide,
  cancelRide,
  deleteRide
} = require('../controllers/rideController');
const { protect } = require('../middleware/auth');
const { 
  validateRideCreation, 
  validateRideUpdate, 
  validateQueryParams,
  validateIdParam
} = require('../middleware/validation');

const router = express.Router();

// All ride routes require authentication
router.use(protect);

// Apply query validation to all routes
router.use(validateQueryParams);

/**
 * @swagger
 * /api/rides:
 *   get:
 *     tags: [Rides]
 *     summary: Get user's rides
 *     description: Retrieve all rides for the authenticated user with optional filtering
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
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter rides from this date (YYYY-MM-DD)
 *         example: "2024-01-01"
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter rides until this date (YYYY-MM-DD)
 *         example: "2024-01-31"
 *     responses:
 *       200:
 *         description: Rides retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     count:
 *                       type: number
 *                       example: 5
 *                     data:
 *                       type: object
 *                       properties:
 *                         rides:
 *                           type: array
 *                           items:
 *                             $ref: '#/components/schemas/Ride'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *   post:
 *     tags: [Rides]
 *     summary: Create a new ride request
 *     description: Book a new ride for the authenticated user
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RideRequest'
 *           example:
 *             pickup:
 *               address: "Office Building A, Sector 5, Bangalore"
 *               latitude: 12.9716
 *               longitude: 77.5946
 *               landmark: "Near Metro Station"
 *             drop:
 *               address: "Kempegowda International Airport, Bangalore"
 *               latitude: 13.1986
 *               longitude: 77.7066
 *               landmark: "Terminal 1"
 *             scheduleTime: "2024-01-15T10:30:00.000Z"
 *             purpose: "Client meeting at airport"
 *             specialRequirements: "Need AC car"
 *     responses:
 *       201:
 *         description: Ride request created successfully
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
 *               message: "Ride request created successfully"
 *               data:
 *                 ride:
 *                   _id: "60d5ecb74d8b8e001c8e4b1b"
 *                   userId: "60d5ecb74d8b8e001c8e4b1a"
 *                   status: "pending"
 *                   estimatedFare: 250
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router
  .route('/')
  .get(getUserRides)
  .post(validateRideCreation, createRide);

/**
 * @swagger
 * /api/rides/{id}:
 *   get:
 *     tags: [Rides]
 *     summary: Get ride details
 *     description: Retrieve detailed information about a specific ride
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Ride ID
 *         example: "60d5ecb74d8b8e001c8e4b1b"
 *     responses:
 *       200:
 *         description: Ride details retrieved successfully
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
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *   put:
 *     tags: [Rides]
 *     summary: Update ride
 *     description: Update a pending ride request (only pickup, drop, and scheduleTime can be updated)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Ride ID
 *         example: "60d5ecb74d8b8e001c8e4b1b"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               pickup:
 *                 $ref: '#/components/schemas/Location'
 *               drop:
 *                 $ref: '#/components/schemas/Location'
 *               scheduleTime:
 *                 type: string
 *                 format: date-time
 *                 example: "2024-01-15T11:00:00.000Z"
 *           example:
 *             pickup:
 *               address: "Office Building B, Sector 6, Bangalore"
 *               latitude: 12.9720
 *               longitude: 77.5950
 *             scheduleTime: "2024-01-15T11:00:00.000Z"
 *     responses:
 *       200:
 *         description: Ride updated successfully
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
 *       400:
 *         description: Can only update pending rides
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               success: false
 *               message: "Can only update pending rides"
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *   delete:
 *     tags: [Rides]
 *     summary: Cancel ride
 *     description: Cancel a ride request (cannot cancel completed or already cancelled rides)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Ride ID
 *         example: "60d5ecb74d8b8e001c8e4b1b"
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reason:
 *                 type: string
 *                 description: Reason for cancellation
 *                 example: "Meeting postponed"
 *           example:
 *             reason: "Meeting postponed"
 *     responses:
 *       200:
 *         description: Ride cancelled successfully
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
 *               message: "Ride cancelled successfully"
 *               data:
 *                 ride:
 *                   _id: "60d5ecb74d8b8e001c8e4b1b"
 *                   status: "cancelled"
 *                   cancellationReason: "Meeting postponed"
 *       400:
 *         description: Cannot cancel this ride
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               success: false
 *               message: "Cannot cancel this ride"
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */

// Permanent deletion route (separate from cancel)
router.delete('/:id/permanent', validateIdParam, deleteRide);

router
  .route('/:id')
  .get(validateIdParam, getRide)
  .put(validateIdParam, validateRideUpdate, updateRide)
  .delete(validateIdParam, cancelRide);

module.exports = router;
