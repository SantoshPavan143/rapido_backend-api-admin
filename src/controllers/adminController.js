const Ride = require('../models/Ride');
const User = require('../models/User');
const AdminAction = require('../models/AdminAction');
const { notifyUserRideUpdate } = require('./notificationController');

// @desc    Get all rides for admin
// @route   GET /api/admin/rides
// @access  Private/Admin
const getAllRides = async (req, res, next) => {
  try {
    const { status, userId, startDate, endDate, department } = req.query;
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const startIndex = (page - 1) * limit;

    // Build query
    const query = {};
    
    if (status) {
      query.status = status;
    }
    
    if (userId) {
      query.userId = userId;
    }
    
    if (startDate || endDate) {
      query.scheduleTime = {};
      if (startDate) query.scheduleTime.$gte = new Date(startDate);
      if (endDate) query.scheduleTime.$lte = new Date(endDate);
    }

    // If filtering by department, first get users from that department
    if (department) {
      const users = await User.find({ department: department }).select('_id');
      query.userId = { $in: users.map(user => user._id) };
    }

    const rides = await Ride.find(query)
      .populate('userId', 'firstName lastName email phone employeeId department')
      .populate('approvedBy', 'firstName lastName email')
      .populate('rejectedBy', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip(startIndex);

    const total = await Ride.countDocuments(query);

    res.status(200).json({
      success: true,
      count: rides.length,
      total,
      pagination: {
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      },
      data: {
        rides
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Approve ride
// @route   PUT /api/admin/rides/:id/approve
// @access  Private/Admin
const approveRide = async (req, res, next) => {
  try {
    const ride = await Ride.findById(req.params.id);

    if (!ride) {
      return res.status(404).json({
        success: false,
        message: 'Ride not found'
      });
    }

    if (ride.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Can only approve pending rides'
      });
    }

    ride.status = 'approved';
    ride.approvedBy = req.user.id;
    ride.approvedAt = new Date();
    ride.adminComments = req.body.comments || '';

    await ride.save();

    // Send notification to user about ride approval
    await notifyUserRideUpdate(ride._id, 'approved', req.user.id);

    // Log admin action
    await AdminAction.create({
      adminId: req.user.id,
      action: 'approve_ride',
      targetType: 'ride',
      targetId: ride._id,
      details: {
        rideId: ride._id,
        userId: ride.userId,
        comments: req.body.comments
      }
    });

    res.status(200).json({
      success: true,
      message: 'Ride approved successfully',
      data: {
        ride
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Reject ride
// @route   PUT /api/admin/rides/:id/reject
// @access  Private/Admin
const rejectRide = async (req, res, next) => {
  try {
    const ride = await Ride.findById(req.params.id);

    if (!ride) {
      return res.status(404).json({
        success: false,
        message: 'Ride not found'
      });
    }

    if (ride.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Can only reject pending rides'
      });
    }

    ride.status = 'rejected';
    ride.rejectedBy = req.user.id;
    ride.rejectedAt = new Date();
    ride.rejectionReason = req.body.reason || 'Not approved';
    ride.adminComments = req.body.comments || '';

    await ride.save();

    // Send notification to user about ride rejection
    await notifyUserRideUpdate(ride._id, 'rejected', req.user.id);

    // Log admin action
    await AdminAction.create({
      adminId: req.user.id,
      action: 'reject_ride',
      targetType: 'ride',
      targetId: ride._id,
      details: {
        rideId: ride._id,
        userId: ride.userId,
        reason: req.body.reason,
        comments: req.body.comments
      }
    });

    res.status(200).json({
      success: true,
      message: 'Ride rejected successfully',
      data: {
        ride
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get ride analytics
// @route   GET /api/admin/analytics
// @access  Private/Admin
const getRideAnalytics = async (req, res, next) => {
  try {
    const { startDate, endDate, department } = req.query;
    
    // Build match query
    const matchQuery = {};
    
    if (startDate || endDate) {
      matchQuery.createdAt = {};
      if (startDate) matchQuery.createdAt.$gte = new Date(startDate);
      if (endDate) matchQuery.createdAt.$lte = new Date(endDate);
    }

    // Basic analytics
    const totalRides = await Ride.countDocuments(matchQuery);
    const pendingRides = await Ride.countDocuments({ ...matchQuery, status: 'pending' });
    const approvedRides = await Ride.countDocuments({ ...matchQuery, status: 'approved' });
    const rejectedRides = await Ride.countDocuments({ ...matchQuery, status: 'rejected' });
    const completedRides = await Ride.countDocuments({ ...matchQuery, status: 'completed' });
    const cancelledRides = await Ride.countDocuments({ ...matchQuery, status: 'cancelled' });

    // Get total users count
    const totalUsers = await User.countDocuments({ role: { $ne: 'admin' } });

    // Department wise analytics
    const departmentAnalytics = await Ride.aggregate([
      { $match: matchQuery },
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'user'
        }
      },
      { $unwind: '$user' },
      {
        $group: {
          _id: '$user.department',
          totalRides: { $sum: 1 },
          totalFare: { $sum: '$estimatedFare' },
          avgFare: { $avg: '$estimatedFare' }
        }
      },
      { $sort: { totalRides: -1 } }
    ]);

    // Status wise analytics over time
    const monthlyAnalytics = await Ride.aggregate([
      { $match: matchQuery },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            status: '$status'
          },
          count: { $sum: 1 },
          totalFare: { $sum: '$estimatedFare' }
        }
      },
      { $sort: { '_id.year': -1, '_id.month': -1 } }
    ]);

    // Total fare calculations
    const fareAnalytics = await Ride.aggregate([
      { $match: { ...matchQuery, status: { $in: ['completed', 'approved'] } } },
      {
        $group: {
          _id: null,
          totalFare: { $sum: '$estimatedFare' },
          avgFare: { $avg: '$estimatedFare' },
          maxFare: { $max: '$estimatedFare' },
          minFare: { $min: '$estimatedFare' }
        }
      }
    ]);

    res.status(200).json({
      success: true,
      data: {
        summary: {
          totalRides,
          pendingRides,
          approvedRides,
          rejectedRides,
          completedRides,
          cancelledRides,
          totalUsers,
          approvalRate: totalRides > 0 ? ((approvedRides / totalRides) * 100).toFixed(2) : 0
        },
        departmentAnalytics,
        monthlyAnalytics,
        fareAnalytics: fareAnalytics[0] || {
          totalFare: 0,
          avgFare: 0,
          maxFare: 0,
          minFare: 0
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get admin actions log
// @route   GET /api/admin/actions
// @access  Private/Admin
const getAdminActions = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const startIndex = (page - 1) * limit;

    const actions = await AdminAction.find()
      .populate('adminId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip(startIndex);

    const total = await AdminAction.countDocuments();

    res.status(200).json({
      success: true,
      count: actions.length,
      total,
      pagination: {
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      },
      data: {
        actions
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get recent activity for dashboard
// @route   GET /api/admin/recent-activity
// @access  Private/Admin
const getRecentActivity = async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 10;
    
    // Get recent rides (status changes)
    const recentRides = await Ride.find({
      status: { $in: ['approved', 'rejected', 'completed', 'in-progress'] },
      updatedAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
    })
      .populate('userId', 'firstName lastName')
      .populate('approvedBy', 'firstName lastName')
      .populate('rejectedBy', 'firstName lastName')
      .sort({ updatedAt: -1 })
      .limit(limit);

    // Get recent admin actions
    const recentActions = await AdminAction.find({
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
    })
      .populate('adminId', 'firstName lastName')
      .sort({ createdAt: -1 })
      .limit(limit);

    // Transform rides into activity format
    const rideActivities = recentRides.map(ride => {
      let activityType = 'ride_update';
      let description = '';
      let icon = 'clock';

      switch (ride.status) {
        case 'approved':
          activityType = 'ride_approved';
          description = `${ride.userId?.firstName} ${ride.userId?.lastName}'s ride to ${ride.destination} was approved`;
          icon = 'check-circle';
          break;
        case 'rejected':
          activityType = 'ride_rejected';
          description = `${ride.userId?.firstName} ${ride.userId?.lastName}'s ride to ${ride.destination} was rejected`;
          icon = 'x-circle';
          break;
        case 'completed':
          activityType = 'ride_completed';
          description = `${ride.userId?.firstName} ${ride.userId?.lastName}'s ride to ${ride.destination} was completed`;
          icon = 'check';
          break;
        case 'in-progress':
          activityType = 'ride_started';
          description = `${ride.userId?.firstName} ${ride.userId?.lastName}'s ride to ${ride.destination} has started`;
          icon = 'truck';
          break;
        default:
          description = `Ride status updated for ${ride.userId?.firstName} ${ride.userId?.lastName}`;
      }

      return {
        id: ride._id,
        type: activityType,
        description,
        icon,
        timestamp: ride.updatedAt,
        data: {
          rideId: ride._id,
          userId: ride.userId?._id,
          userName: `${ride.userId?.firstName} ${ride.userId?.lastName}`,
          destination: ride.destination,
          status: ride.status
        }
      };
    });

    // Transform admin actions into activity format
    const adminActivities = recentActions.map(action => {
      let description = '';
      let icon = 'user';

      switch (action.action) {
        case 'approve_ride':
          description = `${action.adminId?.firstName} ${action.adminId?.lastName} approved a ride request`;
          icon = 'check-circle';
          break;
        case 'reject_ride':
          description = `${action.adminId?.firstName} ${action.adminId?.lastName} rejected a ride request`;
          icon = 'x-circle';
          break;
        case 'create_user':
          description = `${action.adminId?.firstName} ${action.adminId?.lastName} created a new user account`;
          icon = 'user-plus';
          break;
        case 'update_user':
          description = `${action.adminId?.firstName} ${action.adminId?.lastName} updated user information`;
          icon = 'user';
          break;
        case 'delete_user':
          description = `${action.adminId?.firstName} ${action.adminId?.lastName} deleted a user account`;
          icon = 'user-minus';
          break;
        default:
          description = `${action.adminId?.firstName} ${action.adminId?.lastName} performed an admin action`;
      }

      return {
        id: action._id,
        type: action.action,
        description,
        icon,
        timestamp: action.createdAt,
        data: {
          adminId: action.adminId?._id,
          adminName: `${action.adminId?.firstName} ${action.adminId?.lastName}`,
          targetType: action.targetType,
          targetId: action.targetId,
          details: action.details
        }
      };
    });

    // Combine and sort all activities
    const allActivities = [...rideActivities, ...adminActivities]
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);

    res.status(200).json({
      success: true,
      data: {
        activities: allActivities,
        total: allActivities.length
      }
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getAllRides,
  approveRide,
  rejectRide,
  getRideAnalytics,
  getAdminActions,
  getRecentActivity
};
