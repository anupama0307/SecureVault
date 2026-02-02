const API_BASE = 'http://127.0.0.1:5000';

export interface User {
    id: number;
    username: string;
    role: 'student' | 'faculty' | 'admin';
}

export interface ApiResponse<T = unknown> {
    success?: boolean;
    error?: string;
    message?: string;
    data?: T;
}

// Generic fetch wrapper
async function fetchApi<T>(
    endpoint: string,
    options: RequestInit = {}
): Promise<T> {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;

    const headers: HeadersInit = {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
    };

    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || 'An error occurred');
    }

    return data;
}

// Auth API
export const authApi = {
    register: (username: string, password: string, role: string, email?: string) =>
        fetchApi<{ success: boolean; user: User }>('/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, password, role, email }),
        }),

    login: (username: string, password: string) =>
        fetchApi<{ success: boolean; requires_otp: boolean; message: string }>('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        }),

    verifyOtp: (username: string, otp: string) =>
        fetchApi<{ success: boolean; token: string; user: User }>('/auth/verify-otp', {
            method: 'POST',
            body: JSON.stringify({ username, otp }),
        }),

    forgotPassword: (username: string) =>
        fetchApi<{ success: boolean; message: string }>('/auth/forgot-password', {
            method: 'POST',
            body: JSON.stringify({ username }),
        }),

    resetPassword: (username: string, otp: string, newPassword: string) =>
        fetchApi<{ success: boolean; message: string }>('/auth/reset-password', {
            method: 'POST',
            body: JSON.stringify({ username, otp, new_password: newPassword }),
        }),

    me: () => fetchApi<{ user: User }>('/auth/me'),

    // WebAuthn
    webauthn: {
        registerOptions: () =>
            fetchApi<any>('/auth/webauthn/register/options', { method: 'POST' }),

        registerVerify: (data: any) =>
            fetchApi<{ success: boolean; message: string }>('/auth/webauthn/register/verify', {
                method: 'POST',
                body: JSON.stringify(data),
            }),

        loginOptions: (username: string) =>
            fetchApi<any>('/auth/webauthn/login/options', {
                method: 'POST',
                body: JSON.stringify({ username }),
            }),

        loginVerify: (username: string, data: any) =>
            fetchApi<{ success: boolean; token: string; user: User }>('/auth/webauthn/login/verify', {
                method: 'POST',
                body: JSON.stringify({ username, ...data }),
            }),
    },
};

// Password Vault API
export interface PasswordEntry {
    id: number;
    site_name: string;
    username: string;
    password: string;
    created_at: string;
    updated_at: string | null;
}

export const passwordsApi = {
    list: () => fetchApi<{ passwords: PasswordEntry[] }>('/passwords'),

    get: (id: number) => fetchApi<{ password: PasswordEntry }>(`/passwords/${id}`),

    create: (siteName: string, username: string, password: string) =>
        fetchApi<{ success: boolean; id: number }>('/passwords', {
            method: 'POST',
            body: JSON.stringify({ site_name: siteName, username, password }),
        }),

    update: (id: number, siteName: string, username: string, password: string) =>
        fetchApi<{ success: boolean }>(`/passwords/${id}`, {
            method: 'PUT',
            body: JSON.stringify({ site_name: siteName, username, password }),
        }),

    delete: (id: number) =>
        fetchApi<{ success: boolean }>(`/passwords/${id}`, {
            method: 'DELETE',
        }),

    generate: (length: number = 16) =>
        fetchApi<{ password: string }>('/passwords/generate', {
            method: 'POST',
            body: JSON.stringify({ length }),
        }),
};

// Resources API
export interface Resource {
    id: number;
    faculty_id: number;
    faculty_name: string;
    resource_type: 'quiz_password' | 'pdf' | 'question_paper';
    subject: string;
    title: string;
    created_at: string;
}

export const resourcesApi = {
    getShared: () => fetchApi<{ resources: Resource[] }>('/resources/shared'),

    getMyUploads: () => fetchApi<{ resources: Resource[] }>('/resources/my-uploads'),

    uploadQuizPassword: (subject: string, title: string, password: string) =>
        fetchApi<{ success: boolean; id: number }>('/resources/quiz-password', {
            method: 'POST',
            body: JSON.stringify({ subject, title, password }),
        }),

    uploadPdf: async (subject: string, title: string, file: File) => {
        const token = localStorage.getItem('token');
        const formData = new FormData();
        formData.append('subject', subject);
        formData.append('title', title);
        formData.append('file', file);

        const response = await fetch(`${API_BASE}/resources/pdf`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
            },
            body: formData,
        });

        return response.json();
    },

    uploadQuestionPaper: async (subject: string, title: string, file: File) => {
        const token = localStorage.getItem('token');
        const formData = new FormData();
        formData.append('subject', subject);
        formData.append('title', title);
        formData.append('file', file);

        const response = await fetch(`${API_BASE}/resources/question-paper`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
            },
            body: formData,
        });

        return response.json();
    },

    decrypt: (id: number) =>
        fetchApi<{
            success: boolean;
            resource_type: string;
            subject: string;
            title: string;
            content?: string;
            file_data?: string;
            integrity_verified: boolean;
        }>(`/resources/decrypt/${id}`, {
            method: 'POST',
        }),

    verify: (id: number) =>
        fetchApi<{ integrity_valid: boolean; message: string }>(`/resources/verify/${id}`),

    getToken: (id: number) =>
        fetchApi<{
            success: boolean;
            resource_id: number;
            title: string;
            resource_type: string;
            token: string;
            token_format: string;
            components: {
                iv: string;
                signature: string;
                ciphertext: string;
            };
        }>(`/resources/token/${id}`),

    verifyToken: (id: number, token: string) =>
        fetchApi<{
            success: boolean;
            valid: boolean;
            resource_id: number;
            resource_type: string;
            message: string;
        }>(`/resources/verify-token/${id}`, {
            method: 'POST',
            body: JSON.stringify({ token }),
        }),

    delete: (id: number) =>
        fetchApi<{ success: boolean }>(`/resources/${id}`, {
            method: 'DELETE',
        }),
};

// Admin API
export const adminApi = {
    getUsers: () =>
        fetchApi<{
            users: Array<{ id: number; username: string; role: string; created_at: string }>;
            by_role: { students: number; faculty: number; admins: number };
        }>('/admin/users'),

    getAuditLogs: (limit: number = 100) =>
        fetchApi<{
            logs: Array<{
                id: number;
                timestamp: string;
                username: string;
                action: string;
                details: string;
                ip_address: string;
            }>;
        }>(`/admin/audit-logs?limit=${limit}`),

    getStats: () =>
        fetchApi<{
            users: { total: number; students: number; faculty: number };
            resources: { total: number; quiz_passwords: number; pdfs: number; question_papers: number };
            security: { recent_login_successes: number; recent_login_failures: number };
        }>('/admin/stats'),

    getAccessControl: () =>
        fetchApi<{
            access_control_matrix: Record<string, Record<string, string[]>>;
            security_concepts: Record<string, Record<string, string>>;
            countermeasures: string[];
        }>('/admin/access-control'),
};

// Utility functions
export const validatePassword = (password: string): { isValid: boolean; errors: string[] } => {
    const errors: string[] = [];

    if (password.length < 8) {
        errors.push('At least 8 characters');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('At least one uppercase letter (A-Z)');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('At least one lowercase letter (a-z)');
    }
    if (!/[!@#$%^&*]/.test(password)) {
        errors.push('At least one special character (!@#$%^&*)');
    }

    return { isValid: errors.length === 0, errors };
};
