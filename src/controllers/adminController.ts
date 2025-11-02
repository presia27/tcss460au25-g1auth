// src/controllers/adminController.ts
import { Response } from 'express';
import { IJwtRequest, UserRole, RoleName } from '@models';
import {
    getPool,
    generateSaltedHash
} from '@utilities';


/**
 * Response types for admin endpoints
 */
export interface AdminUserResponse {
    account_id: number;
    firstname: string;
    lastname: string;
    username: string;
    email: string;
    email_verified: boolean;
    phone: string | null;
    phone_verified: boolean;
    account_role: UserRole;
    role_name: string;
    account_status: string;
    created_at: string;
    updated_at: string;
}

export interface AdminUsersListResponse {
    count: number;
    page: number;
    limit: number;
    data: AdminUserResponse[];
}

export interface AdminDashboardStats {
    totalUsers: number;
    activeUsers: number;
    deletedUsers: number;
    suspendedUsers: number;
    verifiedEmails: number;
    verifiedPhones: number;
    usersByRole: {
        role: UserRole;
        role_name: string;
        count: number;
    }[];
    recentRegistrations: {
        today: number;
        thisWeek: number;
        thisMonth: number;
    };
}

/**
 * Helper function to format user data with role name
 */
const formatUserResponse = (user: any): AdminUserResponse => {
    return {
        account_id: user.account_id,
        firstname: user.firstname,
        lastname: user.lastname,
        username: user.username,
        email: user.email,
        email_verified: user.email_verified,
        phone: user.phone,
        phone_verified: user.phone_verified,
        account_role: user.account_role,
        role_name: RoleName[user.account_role as keyof typeof RoleName] || 'Unknown',
        account_status: user.account_status,
        created_at: user.created_at,
        updated_at: user.updated_at
    };
};

/**
 * Create a new user with specified role (admin only)
 * POST /admin/users/create
 */
export const createUser = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    const pool = getPool();
    const client = await pool.connect();

    try {
        const {
            firstname,
            lastname,
            username,
            email,
            password,
            phone,
            role
        } = request.body;

        // Start transaction
        await client.query('BEGIN');

        // Check if username or email already exists
        const existingUser = await client.query(
            `SELECT account_id FROM account 
             WHERE username = $1 OR email = $2`,
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return response.status(409).json({
                success: false,
                message: 'Username or email already exists'
            });
        }

        // Create account
        const accountResult = await client.query(
            `INSERT INTO account 
             (firstname, lastname, username, email, phone, account_role, account_status, email_verified, phone_verified)
             VALUES ($1, $2, $3, $4, $5, $6, 'active', false, false)
             RETURNING account_id, firstname, lastname, username, email, phone, account_role, account_status, 
                       email_verified, phone_verified, created_at, updated_at`,
            [firstname, lastname, username, email, phone || null, role]
        );

        const newAccount = accountResult.rows[0];

        // Hash password and create credentials
        const { salt, hash } = await generateSaltedHash(password);
        await client.query(
            `INSERT INTO account_credential (account_id, salted_hash, salt)
             VALUES ($1, $2, $3)`,
            [newAccount.account_id, hash, salt]
        );

        await client.query('COMMIT');

        return response.status(201).json({
            success: true,
            message: 'User created successfully',
            data: formatUserResponse(newAccount)
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Create user error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to create user'
        });
    } finally {
        client.release();
    }
};

/**
 * List all users with pagination and optional filters
 * GET /admin/users
 */
export const listUsers = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    try {
        const pool = getPool();
        
        // Pagination
        const page = Math.max(parseInt(request.query.page as string) || 1, 1);
        const limit = Math.min(Math.max(parseInt(request.query.limit as string) || 50, 1), 100);
        const offset = (page - 1) * limit;

        // Filters
        const role = request.query.role ? parseInt(request.query.role as string) : null;
        const status = request.query.status as string;
        const verified = request.query.verified as string;

        // Build dynamic query
        const conditions: string[] = [];
        const values: any[] = [];
        let paramCount = 1;

        if (role !== null && !isNaN(role)) {
            conditions.push(`account_role = $${paramCount++}`);
            values.push(role);
        }

        if (status) {
            conditions.push(`account_status = $${paramCount++}`);
            values.push(status);
        }

        if (verified === 'email') {
            conditions.push(`email_verified = true`);
        } else if (verified === 'phone') {
            conditions.push(`phone_verified = true`);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

        // Get total count
        const countResult = await pool.query(
            `SELECT COUNT(*) FROM account ${whereClause}`,
            values
        );
        const totalCount = parseInt(countResult.rows[0].count);

        // Get users
        values.push(limit, offset);
        const usersResult = await pool.query(
            `SELECT account_id, firstname, lastname, username, email, phone, 
                    account_role, account_status, email_verified, phone_verified,
                    created_at, updated_at
             FROM account
             ${whereClause}
             ORDER BY created_at DESC
             LIMIT $${paramCount++} OFFSET $${paramCount++}`,
            values
        );

        const users = usersResult.rows.map(formatUserResponse);

        return response.json({
            success: true,
            count: totalCount,
            page,
            limit,
            data: users
        });

    } catch (error) {
        console.error('List users error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to retrieve users'
        });
    }
};

/**
 * Search users by name, username, or email
 * GET /admin/users/search
 */
export const searchUsers = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    try {
        const pool = getPool();
        const query = request.query.q as string;

        if (!query || query.trim().length === 0) {
            return response.status(400).json({
                success: false,
                message: 'Search query is required'
            });
        }

        const searchTerm = `%${query.trim()}%`;

        const result = await pool.query(
            `SELECT account_id, firstname, lastname, username, email, phone,
                    account_role, account_status, email_verified, phone_verified,
                    created_at, updated_at
             FROM account
             WHERE firstname ILIKE $1 
                OR lastname ILIKE $1 
                OR username ILIKE $1 
                OR email ILIKE $1
             ORDER BY created_at DESC
             LIMIT 50`,
            [searchTerm]
        );

        const users = result.rows.map(formatUserResponse);

        return response.json({
            success: true,
            count: users.length,
            query: query,
            data: users
        });

    } catch (error) {
        console.error('Search users error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to search users'
        });
    }
};

/**
 * Get detailed information about a specific user
 * GET /admin/users/:id
 */
export const getUserById = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    try {
        const pool = getPool();
        const userId = parseInt(request.params.id);

        const result = await pool.query(
            `SELECT account_id, firstname, lastname, username, email, phone,
                    account_role, account_status, email_verified, phone_verified,
                    created_at, updated_at
             FROM account
             WHERE account_id = $1`,
            [userId]
        );

        if (result.rows.length === 0) {
            return response.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        return response.json({
            success: true,
            data: formatUserResponse(result.rows[0])
        });

    } catch (error) {
        console.error('Get user error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to retrieve user'
        });
    }
};

/**
 * Update user information
 * PUT /admin/users/:id
 */
export const updateUser = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    try {
        const pool = getPool();
        const userId = parseInt(request.params.id);
        const {
            firstname,
            lastname,
            username,
            email,
            phone,
            account_status,
            email_verified,
            phone_verified
        } = request.body;

        // Build dynamic update query
        const updates: string[] = [];
        const values: any[] = [];
        let paramCount = 1;

        if (firstname !== undefined) {
            updates.push(`firstname = $${paramCount++}`);
            values.push(firstname);
        }
        if (lastname !== undefined) {
            updates.push(`lastname = $${paramCount++}`);
            values.push(lastname);
        }
        if (username !== undefined) {
            updates.push(`username = $${paramCount++}`);
            values.push(username);
        }
        if (email !== undefined) {
            updates.push(`email = $${paramCount++}`);
            values.push(email);
        }
        if (phone !== undefined) {
            updates.push(`phone = $${paramCount++}`);
            values.push(phone);
        }
        if (account_status !== undefined) {
            updates.push(`account_status = $${paramCount++}`);
            values.push(account_status);
        }
        if (email_verified !== undefined) {
            updates.push(`email_verified = $${paramCount++}`);
            values.push(email_verified);
        }
        if (phone_verified !== undefined) {
            updates.push(`phone_verified = $${paramCount++}`);
            values.push(phone_verified);
        }

        if (updates.length === 0) {
            return response.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }

        updates.push(`updated_at = CURRENT_TIMESTAMP`);
        values.push(userId);

        const result = await pool.query(
            `UPDATE account 
             SET ${updates.join(', ')}
             WHERE account_id = $${paramCount}
             RETURNING account_id, firstname, lastname, username, email, phone,
                       account_role, account_status, email_verified, phone_verified,
                       created_at, updated_at`,
            values
        );

        if (result.rows.length === 0) {
            return response.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        return response.json({
            success: true,
            message: 'User updated successfully',
            data: formatUserResponse(result.rows[0])
        });

    } catch (error) {
        console.error('Update user error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to update user'
        });
    }
};

/**
 *  delete a user (set account_status to 'deleted')
 * DELETE /admin/users/:id
 */
export const deleteUser = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    try {
        const pool = getPool();
        const userId = parseInt(request.params.id);

        const result = await pool.query(
            `UPDATE account 
             SET account_status = 'deleted', updated_at = CURRENT_TIMESTAMP
             WHERE account_id = $1
             RETURNING account_id, username, email`,
            [userId]
        );

        if (result.rows.length === 0) {
            return response.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        return response.json({
            success: true,
            message: 'User deleted successfully',
            data: {
                account_id: result.rows[0].account_id,
                username: result.rows[0].username,
                email: result.rows[0].email
            }
        });

    } catch (error) {
        console.error('Delete user error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to delete user'
        });
    }
};

/**
 * Admin password reset - set new password for a user
 * PUT /admin/users/:id/password
 */
export const resetUserPassword = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    const pool = getPool();
    const client = await pool.connect();

    try {
        const userId = parseInt(request.params.id);
        const { password } = request.body;

        await client.query('BEGIN');

        // Check if user exists
        const userCheck = await client.query(
            'SELECT account_id FROM account WHERE account_id = $1',
            [userId]
        );

        if (userCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return response.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Hash new password
        const { salt, hash } = await generateSaltedHash(password);

        // Update credentials
        await client.query(
            `UPDATE account_credential 
             SET salted_hash = $1, salt = $2
             WHERE account_id = $3`,
            [hash, salt, userId]
        );

        await client.query('COMMIT');

        return response.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Reset password error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to reset password'
        });
    } finally {
        client.release();
    }
};

/**
 * Change user's role
 * PUT /admin/users/:id/role
 */
export const changeUserRole = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    try {
        const pool = getPool();
        const userId = parseInt(request.params.id);
        const { role } = request.body;

        const result = await pool.query(
            `UPDATE account 
             SET account_role = $1, updated_at = CURRENT_TIMESTAMP
             WHERE account_id = $2
             RETURNING account_id, username, email, account_role`,
            [role, userId]
        );

        if (result.rows.length === 0) {
            return response.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        return response.json({
            success: true,
            message: 'Role updated successfully',
            data: {
                account_id: result.rows[0].account_id,
                username: result.rows[0].username,
                email: result.rows[0].email,
                new_role: result.rows[0].account_role,
                role_name: RoleName[result.rows[0].account_role as keyof typeof RoleName]
            }
        });

    } catch (error) {
        console.error('Change role error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to change role'
        });
    }
};

/**
 * Get dashboard statistics
 * GET /admin/users/stats/dashboard
 */
export const getDashboardStats = async (
    request: IJwtRequest,
    response: Response
): Promise<Response> => {
    try {
        const pool = getPool();

        // Total users
        const totalResult = await pool.query(
            'SELECT COUNT(*) as count FROM account'
        );

        // Users by status
        const statusResult = await pool.query(
            `SELECT account_status, COUNT(*) as count 
             FROM account 
             GROUP BY account_status`
        );

        // Verified counts
        const verifiedResult = await pool.query(
            `SELECT 
                COUNT(*) FILTER (WHERE email_verified = true) as verified_emails,
                COUNT(*) FILTER (WHERE phone_verified = true) as verified_phones
             FROM account`
        );

        // Users by role
        const roleResult = await pool.query(
            `SELECT account_role, COUNT(*) as count 
             FROM account 
             GROUP BY account_role 
             ORDER BY account_role`
        );

        // Recent registrations
        const recentResult = await pool.query(
            `SELECT 
                COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE) as today,
                COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '7 days') as this_week,
                COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '30 days') as this_month
             FROM account`
        );

        // Build status counts
        const statusCounts = {
            active: 0,
            deleted: 0,
            suspended: 0
        };

        statusResult.rows.forEach(row => {
            const status = row.account_status.toLowerCase();
            if (status in statusCounts) {
                statusCounts[status as keyof typeof statusCounts] = parseInt(row.count);
            }
        });

        // Build role counts
        const usersByRole = roleResult.rows.map(row => ({
            role: row.account_role as UserRole,
            role_name: RoleName[row.account_role as keyof typeof RoleName] || 'Unknown',
            count: parseInt(row.count)
        }));

        const stats: AdminDashboardStats = {
            totalUsers: parseInt(totalResult.rows[0].count),
            activeUsers: statusCounts.active,
            deletedUsers: statusCounts.deleted,
            suspendedUsers: statusCounts.suspended,
            verifiedEmails: parseInt(verifiedResult.rows[0].verified_emails),
            verifiedPhones: parseInt(verifiedResult.rows[0].verified_phones),
            usersByRole,
            recentRegistrations: {
                today: parseInt(recentResult.rows[0].today),
                thisWeek: parseInt(recentResult.rows[0].this_week),
                thisMonth: parseInt(recentResult.rows[0].this_month)
            }
        };

        return response.json({
            success: true,
            data: stats
        });

    } catch (error) {
        console.error('Dashboard stats error:', error);
        return response.status(500).json({
            success: false,
            message: 'Failed to retrieve dashboard statistics'
        });
    }
};