// src/core/middleware/adminAuth.ts
import { Response, NextFunction } from 'express';
import { IJwtRequest } from '@models';

import { UserRole, RoleName } from '@models';

/**
 * Role hierarchy constants (using existing UserRole enum)
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
                required: ROLE_NAMES[minRole],
                current: ROLE_NAMES[request.claims.role]
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
            yourRole: ROLE_NAMES[request.claims.role],
            attemptedRole: ROLE_NAMES[targetRole]
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
 * Combined middleware for admin operations that modify users
 * Requires moderator role, prevents self-modification, and validates role hierarchy
 */
export const requireAdminForUserModification = [
    requireRole(ROLES.MODERATOR),
    preventSelfModification,
    canManageRole
];