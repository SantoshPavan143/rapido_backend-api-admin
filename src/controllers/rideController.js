const Ride = require('../models/Ride');
const { notifyAdminNewRide } = require('./notificationController');

const createRide = async (req, res, next) => {
  try {
    req.body.userId = req.user.id;
    
    // Calculate estimated fare (simple calculation)
    req.body.estimatedFare = Math.floor(Math.random() * 300) + 100; // Random fare between 100-400

    const ride = await Ride.create(req.body);

    // Send notification to admin about new ride request
    await notifyAdminNewRide(ride._id);

    res.status(201).json({
      success: true,
      message: 'Ride created successfully',
      data: {
        ride
      }
    });
  } catch (error) {
    console.error('Create ride error:', error.message);
    next(error);
  }
};
const getUserRides = async (req, res, next) => {
  try {
    const { status, startDate, endDate } = req.query;
    
    // Build query
    const query = { userId: req.user.id };
    
    if (status) {
      query.status = status;
    }
    
    if (startDate || endDate) {
      query.scheduleTime = {};
      if (startDate) query.scheduleTime.$gte = new Date(startDate);
      if (endDate) query.scheduleTime.$lte = new Date(endDate);
    }

    const rides = await Ride.find(query)
      .populate('userId', 'firstName lastName email phone employeeId department')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: rides.length,
      message: 'Rides retrieved successfully',
      data: {
        rides
      }
    });
  } catch (error) {
    console.error('Get rides error:', error.message);
    next(error);
  }
};

const getRide = async (req, res, next) => {
  try {
    const ride = await Ride.findById(req.params.id)
      .populate('userId', 'firstName lastName email phone employeeId department')
      .populate('approvedBy', 'firstName lastName email')
      .populate('rejectedBy', 'firstName lastName email');

    if (!ride) {
      return res.status(404).json({
        success: false,
        message: 'Ride not found'
      });
    }

    // Check if user owns the ride or is admin
    if (ride.userId._id.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        ride
      }
    });
  } catch (error) {
    next(error);
  }
};

const updateRide = async (req, res, next) => {
  try {
    let ride = await Ride.findById(req.params.id);

    if (!ride) {
      return res.status(404).json({
        success: false,
        message: 'Ride not found'
      });
    }

    // Check if user owns the ride
    if (ride.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Only allow updates if ride is pending
    if (ride.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Can only update pending rides'
      });
    }

    // Update allowed fields only
    const allowedFields = ['pickup', 'drop', 'scheduleTime'];
    const updates = {};
    allowedFields.forEach(field => {
      if (req.body[field]) updates[field] = req.body[field];
    });

    ride = await Ride.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true
    });

    res.status(200).json({
      success: true,
      data: {
        ride
      }
    });
  } catch (error) {
    next(error);
  }
};
const cancelRide = async (req, res, next) => {
  try {
    const ride = await Ride.findById(req.params.id);

    if (!ride) {
      return res.status(404).json({
        success: false,
        message: 'Ride not found'
      });
    }
    // Check if user owns the ride
    if (ride.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }
    // Check if ride can be cancelled
    if (['completed', 'cancelled'].includes(ride.status)) {
      return res.status(400).json({
        success: false,
        message: 'Cannot cancel this ride'
      });
    }

    ride.status = 'cancelled';
    ride.cancelledAt = new Date();
    ride.cancellationReason = req.body.reason || 'Cancelled by user';

    await ride.save();

    res.status(200).json({
      success: true,
      message: 'Ride cancelled successfully',
      data: {
        ride
      }
    });
  } catch (error) {
    next(error);
  }
};

const deleteRide = async (req, res, next) => {
  try {
    const ride = await Ride.findById(req.params.id);

    if (!ride) {
      return res.status(404).json({
        success: false,
        message: 'Ride not found'
      });
    }

    // Check if user owns the ride
    if (ride.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Only allow deletion of cancelled rides
    if (ride.status !== 'cancelled') {
      return res.status(400).json({
        success: false,
        message: 'Only cancelled rides can be deleted'
      });
    }

    await Ride.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: 'Ride deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createRide,
  getUserRides,
  getRide,
  updateRide,
  cancelRide,
  deleteRide
};
