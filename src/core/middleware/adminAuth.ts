// src/core/middleware/adminAuth.ts
import { Response, NextFunction } from 'express';
import { IJwtRequest, UserRole, RoleName } from '@models';
import { getPool } from '@db';

/**
 * Role hierarchy constants
 */
export const ROLES = UserRole;

/**
 * Role names (using existing RoleName mapping)
 */
export const ROLE_NAMES = RoleName;

/**
 * Check if user has minimum required role
 */
export const requireRole = (minRole: number) => {
    return (
        request: IJwtRequest,
        response: Response,
        next: NextFunction
    ): void | Response => {
        if (!request.claims) {
            return response.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        if (request.claims.role < minRole) {
            return response.status(403).json({
                success: false,
                message: 'Insufficient permissions',
                required: RoleName[minRole as keyof typeof RoleName],
                current: RoleName[request.claims.role]
            });
        }

        next();
    };
};

/**
 * Middleware to check if user can manage a target role
 * Rule: Admins can only create/modify users with roles <= their own role
 */
export const canManageRole = (
    request: IJwtRequest,
    response: Response,
    next: NextFunction
): void | Response => {
    if (!request.claims) {
        return response.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }

    const targetRole = request.body.role || request.body.account_role;

    // If no role is being set/modified, continue
    if (targetRole === undefined) {
        return next();
    }

    // Validate role is a valid number
    if (!Number.isInteger(targetRole) || targetRole < 1 || targetRole > 5) {
        return response.status(400).json({
            success: false,
            message: 'Invalid role value. Role must be an integer between 1 and 5'
        });
    }

    // Check if user can manage this role
    if (targetRole > request.claims.role) {
        return response.status(403).json({
            success: false,
            message: 'Cannot assign role higher than your own',
            yourRole: RoleName[request.claims.role],
            attemptedRole: RoleName[targetRole as keyof typeof RoleName]
        });
    }

    next();
};

/**
 * Middleware to prevent users from modifying their own account
 * Used for role changes and deletions to prevent self-demotion/deletion
 */
export const preventSelfModification = (
    request: IJwtRequest,
    response: Response,
    next: NextFunction
): void | Response => {
    if (!request.claims) {
        return response.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }

    const targetUserId = parseInt(request.params.id);

    if (targetUserId === request.claims.id) {
        return response.status(403).json({
            success: false,
            message: 'Cannot modify your own account through admin endpoints. Use the user profile endpoints to modify your own account'
        });
    }

    next();
};

/**
 * Middleware to check if user can modify target user based on their role
 * Fetches target user's role from database and ensures admin has sufficient privileges
 */
export const canModifyTargetUser = async (
    request: IJwtRequest,
    response: Response,
    next: NextFunction
): Promise<void | Response> => {
    if (!request.claims) {
        return response.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }

    const targetUserId = parseInt(request.params.id);

    try {
        const pool = getPool();
        
        // Fetch target user's role
        const result = await pool.query(
            'SELECT account_role FROM account WHERE account_id = $1',
            [targetUserId]
        );

        // If user doesn't exist, let the controller handle 404
        if (result.rows.length === 0) {
            return next();
        }

        const targetUserRole = result.rows[0].account_role;

        // Check if admin can manage this user's role
        if (targetUserRole > request.claims.role) {
            return response.status(403).json({
                success: false,
                message: 'Cannot modify user with higher role than yours',
                yourRole: RoleName[request.claims.role],
                targetRole: RoleName[targetUserRole as keyof typeof RoleName]
            });
        }

        // Store target user's role in request for potential use by controller
        (request as any).targetUserRole = targetUserRole;

        next();
    } catch (error) {
        console.error('Error checking target user role:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to verify permissions'
        });
    }
};

/**
 * Combined middleware for admin operations that modify users
 * Requires moderator role, prevents self-modification, validates role hierarchy,
 * and checks target user's role from database
 */
export const requireAdminForUserModification = [
    requireRole(ROLES.MODERATOR),
    preventSelfModification,
    canModifyTargetUser,  // Check target user's role
    canManageRole         // Still check body role if present (for role changes)
];