const User = require('../models/User');
const Ride = require('../models/Ride');

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
const getUsers = async (req, res, next) => {
  try {
    const { department, role, isActive, search, page = 1, limit = 10 } = req.query;
    
    // Build query
    const query = {};
    
    // Always exclude admin users from the list
    query.role = { $ne: 'admin' };
    
    if (department) {
      query.department = department;
    }
    
    if (role && role !== 'admin') {
      query.role = role;
    }
    
    if (isActive !== undefined && isActive !== '') {
      query.isActive = isActive === 'true';
    } else {
      // Default to active users if not specified
      query.isActive = true;
    }
    
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { employeeId: { $regex: search, $options: 'i' } }
      ];
    }

    const startIndex = (parseInt(page, 10) - 1) * parseInt(limit, 10);
    
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit, 10))
      .skip(startIndex);

    const total = await User.countDocuments(query);

    res.status(200).json({
      success: true,
      count: users.length,
      total,
      pagination: {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        totalPages: Math.ceil(total / parseInt(limit, 10))
      },
      data: {
        users
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get single user
// @route   GET /api/users/:id
// @access  Private/Admin
const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Create user
// @route   POST /api/users
// @access  Private/Admin
const createUser = async (req, res, next) => {
  try {
    const user = await User.create(req.body);

    res.status(201).json({
      success: true,
      data: {
        user
      }
    });
  } catch (error) {
    next(error);
  }
};


const updateUser = async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Delete user (soft delete)
// @route   DELETE /api/users/:id
// @access  Private/Admin
const deleteUser = async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive: false },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'User deactivated successfully'
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Delete own account permanently
// @route   DELETE /api/users/delete-account
// @access  Private (user can delete their own account)
const deleteOwnAccount = async (req, res, next) => {
  try {
    const userId = req.user.id;
    
    // First, delete all user's rides
    await Ride.deleteMany({ userId: userId });
    
    // Then delete the user account
    await User.findByIdAndDelete(userId);

    res.status(200).json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getAllUsers: getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  deleteOwnAccount
};
