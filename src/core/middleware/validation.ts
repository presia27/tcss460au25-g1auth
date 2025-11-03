// src/core/middleware/validation.ts
import { body, param, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { SMS_GATEWAYS } from '@models';

/**
 * Middleware to handle validation errors
 * Add this after validation rules to check for errors
 */
export const handleValidationErrors = (request: Request, response: Response, next: NextFunction) => {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
        return response.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: errors.array().map(err => ({
                field: err.type === 'field' ? err.path : undefined,
                message: err.msg
            }))
        });
    }
    next();
};

// ============================================
// AUTH VALIDATION
// ============================================

/**
 * Login validation
 * - Email: required, valid email format, normalized
 * - Password: required
 */
export const validateLogin = [
    body('email')
        .notEmpty()
        .withMessage('Email is required')
        .isEmail()
        .withMessage('Must be a valid email address')
        .normalizeEmail(),
    body('password')
        .notEmpty()
        .withMessage('Password is required'),
    handleValidationErrors
];

/**
 * Public registration validation (no role field allowed)
 * - firstname: required, 1-100 characters
 * - lastname: required, 1-100 characters
 * - email: required, valid email format, normalized
 * - username: required, 3-50 characters, alphanumeric with underscore/hyphen
 * - password: required, 8-128 characters
 * - phone: required, at least 10 digits
 * NOTE: No role validation - public registration always creates basic users
 */
export const validateRegister = [
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
        .notEmpty()
        .withMessage('Phone number is required')
        .matches(/\d{10,}/)
        .withMessage('Phone number must contain at least 10 digits'),
    handleValidationErrors
];

// ============================================
// PASSWORD VALIDATION
// ============================================

/**
 * Password reset request validation
 * - Email: required, valid email format, normalized
 */
export const validatePasswordResetRequest = [
    body('email')
        .notEmpty()
        .withMessage('Email is required')
        .isEmail()
        .withMessage('Must be a valid email address')
        .normalizeEmail(),
    handleValidationErrors
];

/**
 * Password reset validation (with token)
 * - token: required, trimmed
 * - password: required, 8-128 characters
 */
export const validatePasswordReset = [
    body('token')
        .notEmpty()
        .withMessage('Reset token is required')
        .trim(),
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be between 8 and 128 characters'),
    handleValidationErrors
];

/**
 * Password change validation (for authenticated users)
 * - oldPassword: required
 * - newPassword: required, 8-128 characters, different from old password
 */
export const validatePasswordChange = [
    body('oldPassword')
        .notEmpty()
        .withMessage('Current password is required'),
    body('newPassword')
        .notEmpty()
        .withMessage('New password is required')
        .isLength({ min: 8, max: 128 })
        .withMessage('New password must be between 8 and 128 characters')
        .custom((value, { req }) => {
            if (value === req.body.oldPassword) {
                throw new Error('New password must be different from current password');
            }
            return true;
        }),
    handleValidationErrors
];

// ============================================
// VERIFICATION VALIDATION
// ============================================

/**
 * Phone verification send validation
 * - carrier: optional, must be valid SMS gateway from SMS_GATEWAYS
 */
export const validatePhoneSend = [
    body('carrier')
        .optional()
        .isIn(Object.values(SMS_GATEWAYS))
        .withMessage(`Carrier must be one of: ${Object.values(SMS_GATEWAYS).join(', ')}`),
    handleValidationErrors
];

/**
 * Phone verification code validation
 * - code: required, trimmed, exactly 6 digits
 */
export const validatePhoneVerify = [
    body('code')
        .notEmpty()
        .withMessage('Verification code is required')
        .trim()
        .matches(/^\d{6}$/)
        .withMessage('Verification code must be exactly 6 digits'),
    handleValidationErrors
];

/**
 * Email verification token validation (query param)
 * - token: required parameter, trimmed
 */
export const validateEmailToken = [
    query('token')
        .notEmpty()
        .withMessage('Verification token is required')
        .trim(),
    handleValidationErrors
];

// ============================================
// USER/PARAMS VALIDATION
// ============================================

/**
 * Validate user ID in params matches JWT claims
 * Use this for routes where users can only access their own resources
 * - id: required, integer
 */
export const validateUserIdParam = [
    param('id')
        .notEmpty()
        .withMessage('User ID is required')
        .isInt()
        .withMessage('User ID must be an integer')
        .toInt(),
    handleValidationErrors
];

// ============================================
// CUSTOM VALIDATORS (OPTIONAL)
// ============================================

/**
 * Custom password strength validator (optional, more strict)
 * Add to password fields if you want stronger validation
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character (@$!%*?&)
 */
export const passwordStrength = body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/\d/)
    .withMessage('Password must contain at least one number')
    .matches(/[@$!%*?&]/)
    .withMessage('Password must contain at least one special character (@$!%*?&)');

/**
 * Sanitize and validate pagination parameters
 * - page: optional, positive integer
 * - limit: optional, integer between 1 and 100
 */
export const validatePagination = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer')
        .toInt(),
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be an integer between 1 and 100')
        .toInt(),
    handleValidationErrors
];




// ============================================
// ADMIN VALIDATION
// ============================================

/**
 * Admin user creation validation
 * Similar to public registration but includes role field
 */
export const validateAdminCreateUser = [
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
 * User update validation (admin)
 * All fields are optional - only provided fields will be updated
 */
export const validateUserUpdate = [
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
        .isIn(['pending', 'active', 'suspended', 'locked', 'deleted'])
        .withMessage('Status must be pending, active, suspended, locked, or deleted'),
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
 * Admin password reset validation
 * Used when admin resets another user's password
 */
export const validateAdminPasswordReset = [
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be between 8 and 128 characters'),
    handleValidationErrors
];

/**
 * Role change validation
 * Validates the new role value
 */
export const validateRoleChange = [
    body('role')
        .notEmpty()
        .withMessage('Role is required')
        .isInt({ min: 1, max: 5 })
        .withMessage('Role must be an integer between 1 and 5')
        .toInt(),
    handleValidationErrors
];