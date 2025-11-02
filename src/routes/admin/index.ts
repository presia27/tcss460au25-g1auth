// src/routes/admin/index.ts
import { Router } from 'express';
import { body } from 'express-validator';
import { checkToken } from '@core/middleware/jwt';
import { UserRole } from '@models';
import {
    requireRole,
    requireAdminForUserModification,
    canManageRole,
    ROLES
} from '@core/middleware/adminAuth';
import {
    validatePagination,
    validateUserIdParam,
    handleValidationErrors
} from '@core/middleware/validation';
import {
    createUser,
    listUsers,
    searchUsers,
    getUserById,
    updateUser,
    deleteUser,
    resetUserPassword,
    changeUserRole,
    getDashboardStats
} from '../../controllers/adminController';

const adminRoutes = Router();

// Apply authentication to all admin routes
adminRoutes.use(checkToken);

/**
 * Admin user creation validation
 * Similar to public registration but includes role field
 */
const validateAdminCreateUser = [
    body('firstname')
        .notEmpty()
        .withMessage('First name is required')
        .isLength({ min: 1, max: 100 })
        .withMessage('First name must be between 1 and 100 characters')
        .trim(),
    body('lastname')
        .notEmpty()
        .withMessage('Last name is required')
        .isLength({ min: 1, max: 100 })
        .withMessage('Last name must be between 1 and 100 characters')
        .trim(),
    body('email')
        .notEmpty()
        .withMessage('Email is required')
        .isEmail()
        .withMessage('Must be a valid email address')
        .normalizeEmail(),
    body('username')
        .notEmpty()
        .withMessage('Username is required')
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Username can only contain letters, numbers, underscores, and hyphens')
        .trim(),
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be between 8 and 128 characters'),
    body('phone')
        .optional()
        .matches(/\d{10,}/)
        .withMessage('Phone number must contain at least 10 digits'),
    body('role')
        .notEmpty()
        .withMessage('Role is required')
        .isInt({ min: 1, max: 5 })
        .withMessage('Role must be an integer between 1 and 5')
        .toInt(),
    handleValidationErrors
];

/**
 * User update validation
 */
const validateUserUpdate = [
    body('firstname')
        .optional()
        .isLength({ min: 1, max: 100 })
        .withMessage('First name must be between 1 and 100 characters')
        .trim(),
    body('lastname')
        .optional()
        .isLength({ min: 1, max: 100 })
        .withMessage('Last name must be between 1 and 100 characters')
        .trim(),
    body('username')
        .optional()
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Username can only contain letters, numbers, underscores, and hyphens')
        .trim(),
    body('email')
        .optional()
        .isEmail()
        .withMessage('Must be a valid email address')
        .normalizeEmail(),
    body('phone')
        .optional()
        .matches(/\d{10,}/)
        .withMessage('Phone number must contain at least 10 digits'),
    body('account_status')
        .optional()
        .isIn(['active', 'deleted', 'suspended'])
        .withMessage('Status must be active, deleted, or suspended'),
    body('email_verified')
        .optional()
        .isBoolean()
        .withMessage('Email verified must be a boolean')
        .toBoolean(),
    body('phone_verified')
        .optional()
        .isBoolean()
        .withMessage('Phone verified must be a boolean')
        .toBoolean(),
    handleValidationErrors
];

/**
 * Password reset validation
 */
const validatePasswordReset = [
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be between 8 and 128 characters'),
    handleValidationErrors
];

/**
 * Role change validation
 */
const validateRoleChange = [
    body('role')
        .notEmpty()
        .withMessage('Role is required')
        .isInt({ min: 1, max: 5 })
        .withMessage('Role must be an integer between 1 and 5')
        .toInt(),
    handleValidationErrors
];

// ============================================
// ADMIN ROUTES
// ============================================

/**
 * GET /admin/users/stats/dashboard
 * Get dashboard statistics
 * Requires: Moderator role (2+)
 */
adminRoutes.get(
    '/users/stats/dashboard',
    requireRole(ROLES.MODERATOR),
    getDashboardStats
);

/**
 * GET /admin/users/search
 * Search users by name, username, or email
 * Requires: Moderator role (2+)
 */
adminRoutes.get(
    '/users/search',
    requireRole(ROLES.MODERATOR),
    searchUsers
);

/**
 * GET /admin/users
 * List all users with pagination and filters
 * Requires: Moderator role (2+)
 */
adminRoutes.get(
    '/users',
    requireRole(ROLES.MODERATOR),
    validatePagination,
    listUsers
);

/**
 * POST /admin/users/create
 * Create a new user with specified role
 * Requires: Moderator role (2+), role hierarchy validation
 */
adminRoutes.post(
    '/users/create',
    requireRole(ROLES.MODERATOR),
    validateAdminCreateUser,
    canManageRole,
    createUser
);

/**
 * GET /admin/users/:id
 * Get detailed information about a specific user
 * Requires: Moderator role (2+)
 */
adminRoutes.get(
    '/users/:id',
    requireRole(ROLES.MODERATOR),
    validateUserIdParam,
    getUserById
);

/**
 * PUT /admin/users/:id
 * Update user information
 * Requires: Moderator role (2+), cannot modify self
 */
adminRoutes.put(
    '/users/:id',
    validateUserIdParam,
    validateUserUpdate,
    requireAdminForUserModification,
    updateUser
);

/**
 * DELETE /admin/users/:id
 * Soft delete a user
 * Requires: Moderator role (2+), cannot delete self
 */
adminRoutes.delete(
    '/users/:id',
    validateUserIdParam,
    requireAdminForUserModification,
    deleteUser
);

/**
 * PUT /admin/users/:id/password
 * Reset user's password (admin override)
 * Requires: Admin role (3+), cannot modify self
 */
adminRoutes.put(
    '/users/:id/password',
    requireRole(ROLES.ADMIN),
    validateUserIdParam,
    validatePasswordReset,
    requireAdminForUserModification,
    resetUserPassword
);

/**
 * PUT /admin/users/:id/role
 * Change user's role
 * Requires: Moderator role (2+), role hierarchy validation, cannot modify self
 */
adminRoutes.put(
    '/users/:id/role',
    validateUserIdParam,
    validateRoleChange,
    requireAdminForUserModification,
    changeUserRole
);

export {  adminRoutes };