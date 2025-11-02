// src/routes/admin/index.ts
import { Router } from 'express';
import { checkToken } from '@core/middleware/jwt';
import {
    requireRole,
    requireAdminForUserModification,
    canManageRole,
    ROLES
} from '@core/middleware/adminAuth';
import {
    validatePagination,
    validateUserIdParam,
    validateAdminCreateUser,
    validateUserUpdate,
    validateAdminPasswordReset,
    validateRoleChange
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
    validateAdminPasswordReset,
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

export { adminRoutes };