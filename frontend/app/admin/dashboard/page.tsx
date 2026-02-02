'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { adminApi } from '@/lib/api';

interface Stats {
    users: { total: number; students: number; faculty: number };
    resources: { total: number; quiz_passwords: number; pdfs: number; question_papers: number };
    security: { recent_login_successes: number; recent_login_failures: number };
}

export default function AdminDashboard() {
    const router = useRouter();
    const [stats, setStats] = useState<Stats | null>(null);
    const [accessControl, setAccessControl] = useState<{
        access_control_matrix: Record<string, Record<string, string[]>>;
        security_concepts: Record<string, Record<string, string>>;
        countermeasures: string[];
    } | null>(null);
    const [loading, setLoading] = useState(true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const [user, setUser] = useState<any>(null);

    useEffect(() => {
        const stored = localStorage.getItem('user');
        if (!stored) {
            router.push('/');
            return;
        }
        const u = JSON.parse(stored);
        if (u.role !== 'admin') {
            router.push('/');
            return;
        }
        setUser(u);
        fetchData();
    }, [router]);

    const fetchData = async () => {
        try {
            const [statsRes, acRes] = await Promise.all([
                adminApi.getStats(),
                adminApi.getAccessControl()
            ]);
            setStats(statsRes);
            setAccessControl(acRes);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = () => {
        localStorage.clear();
        router.push('/');
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center gradient-bg">
                <div className="spinner" style={{ width: 40, height: 40 }} />
            </div>
        );
    }

    return (
        <div className="min-h-screen gradient-bg gradient-admin">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-logo">
                    <span>🔐</span>
                    SecureVault
                </div>

                <nav className="sidebar-nav">
                    <li className="sidebar-item">
                        <Link href="/admin/dashboard" className="sidebar-link active">
                            <span>📊</span>
                            Dashboard
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/admin/users" className="sidebar-link">
                            <span>👥</span>
                            User Management
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/admin/audit-logs" className="sidebar-link">
                            <span>📋</span>
                            Audit Logs
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/profile" className="sidebar-link">
                            <span>👤</span>
                            Profile
                        </Link>
                    </li>
                </nav>

                <div className="sidebar-footer">
                    <div className="sidebar-user admin">
                        <div className="sidebar-username">{user?.username}</div>
                        <div className="sidebar-role">Administrator</div>
                    </div>
                    <button onClick={handleLogout} className="btn btn-secondary w-full text-sm">
                        Logout
                    </button>
                </div>
            </div>

            {/* Main Content */}
            <main className="main-with-sidebar">
                <div className="page-header">
                    <h1 className="page-title">👑 Admin Dashboard</h1>
                    <p className="page-subtitle">System overview and security monitoring</p>
                </div>

                {/* Stats */}
                <div className="stats-grid mb-8">
                    <div className="stat-card">
                        <div className="stat-value">{stats?.users.total || 0}</div>
                        <div className="stat-label">Total Users</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value text-blue-400">{stats?.users.students || 0}</div>
                        <div className="stat-label">Students</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value text-purple-400">{stats?.users.faculty || 0}</div>
                        <div className="stat-label">Faculty</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value text-green-400">{stats?.resources.total || 0}</div>
                        <div className="stat-label">Resources</div>
                    </div>
                </div>

                {/* Security Stats */}
                <h2 className="text-lg font-semibold mb-4">🔐 Security Overview</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                    <div className="card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-2xl font-bold text-green-400">
                                    {stats?.security.recent_login_successes || 0}
                                </div>
                                <div className="text-sm text-gray-500">Successful Logins (24h)</div>
                            </div>
                            <span className="text-3xl">✓</span>
                        </div>
                    </div>
                    <div className="card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-2xl font-bold text-red-400">
                                    {stats?.security.recent_login_failures || 0}
                                </div>
                                <div className="text-sm text-gray-500">Failed Logins (24h)</div>
                            </div>
                            <span className="text-3xl">⚠️</span>
                        </div>
                    </div>
                </div>

                {/* Access Control Matrix */}
                <h2 className="text-lg font-semibold mb-4">📋 Access Control Matrix</h2>
                <div className="card mb-8 overflow-x-auto">
                    <table className="table">
                        <thead>
                            <tr>
                                <th>Resource</th>
                                <th className="text-center">
                                    <span className="badge badge-student">Student</span>
                                </th>
                                <th className="text-center">
                                    <span className="badge badge-faculty">Faculty</span>
                                </th>
                                <th className="text-center">
                                    <span className="badge badge-admin">Admin</span>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {accessControl && (() => {
                                // Transpose the matrix: backend returns {role: {resource: actions[]}}
                                // We need to display {resource: {role: actions[]}}
                                const acm = accessControl.access_control_matrix;
                                const resources = ['passwords', 'resources', 'users', 'audit_logs'];
                                const resourceLabels: Record<string, string> = {
                                    'passwords': 'Password Vault',
                                    'resources': 'Shared Resources',
                                    'users': 'User Management',
                                    'audit_logs': 'Audit Logs'
                                };

                                return resources.map((resource) => {
                                    const studentActions = acm.student?.[resource] || [];
                                    const facultyActions = acm.faculty?.[resource] || [];
                                    const adminActions = acm.admin?.[resource] || [];

                                    return (
                                        <tr key={resource}>
                                            <td className="font-medium">{resourceLabels[resource] || resource}</td>
                                            <td className="text-center">
                                                {studentActions.length > 0 ? (
                                                    <span className="text-green-400">{studentActions.join(', ')}</span>
                                                ) : (
                                                    <span className="text-red-400">-</span>
                                                )}
                                            </td>
                                            <td className="text-center">
                                                {facultyActions.length > 0 ? (
                                                    <span className="text-green-400">{facultyActions.join(', ')}</span>
                                                ) : (
                                                    <span className="text-red-400">-</span>
                                                )}
                                            </td>
                                            <td className="text-center">
                                                {adminActions.length > 0 ? (
                                                    <span className="text-green-400">{adminActions.join(', ')}</span>
                                                ) : (
                                                    <span className="text-red-400">-</span>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                });
                            })()}
                        </tbody>
                    </table>
                </div>

                {/* Security Concepts */}
                <h2 className="text-lg font-semibold mb-4">🔒 Security Concepts</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                    {accessControl && Object.entries(accessControl.security_concepts).map(([category, concepts]) => (
                        <div key={category} className="card">
                            <h3 className="font-medium text-orange-400 mb-3 capitalize">{category.replace('_', ' ')}</h3>
                            <ul className="space-y-2">
                                {Object.entries(concepts).map(([key, value]) => (
                                    <li key={key} className="text-sm">
                                        <span className="text-gray-400">{key}:</span>{' '}
                                        <span className="text-gray-300">{value}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </div>

                {/* Countermeasures */}
                <h2 className="text-lg font-semibold mb-4">🛡️ Attack Countermeasures</h2>
                <div className="card mb-8 overflow-x-auto">
                    <table className="table">
                        <thead>
                            <tr>
                                <th>Attack</th>
                                <th>Countermeasure</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td className="font-medium text-red-400">Brute Force</td>
                                <td className="text-gray-300">PBKDF2 with 100k iterations</td>
                            </tr>
                            <tr>
                                <td className="font-medium text-red-400">Rainbow Table</td>
                                <td className="text-gray-300">Random salt per password</td>
                            </tr>
                            <tr>
                                <td className="font-medium text-red-400">SQL Injection</td>
                                <td className="text-gray-300">Parameterized queries</td>
                            </tr>
                            <tr>
                                <td className="font-medium text-red-400">Token Tampering</td>
                                <td className="text-gray-300">RSA digital signature</td>
                            </tr>
                            <tr>
                                <td className="font-medium text-red-400">Session Hijacking</td>
                                <td className="text-gray-300">JWT with 24h expiry</td>
                            </tr>
                            <tr>
                                <td className="font-medium text-red-400">MFA Bypass</td>
                                <td className="text-gray-300">OTP with 5-min expiry</td>
                            </tr>
                            <tr>
                                <td className="font-medium text-red-400">Privilege Escalation</td>
                                <td className="text-gray-300">Role-based access control</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                {/* Token Format */}
                <h2 className="text-lg font-semibold mb-4">📦 QP Token Format</h2>
                <div className="card mb-8">
                    <div className="p-4 bg-gray-900/50 rounded-lg border border-gray-700 mb-4">
                        <code className="text-sm text-blue-400">
                            Base64( IV[16 bytes] + Signature[256 bytes] + Ciphertext )
                        </code>
                        <button
                            onClick={() => navigator.clipboard.writeText('Base64( IV[16 bytes] + Signature[256 bytes] + Ciphertext )')}
                            className="ml-3 text-gray-500 hover:text-gray-300 text-sm"
                        >
                            📋
                        </button>
                    </div>
                    <ol className="list-decimal list-inside space-y-2 text-sm text-gray-400">
                        <li><strong>IV</strong>: Random initialization vector for AES</li>
                        <li><strong>Signature</strong>: RSA-PSS signature of ciphertext</li>
                        <li><strong>Ciphertext</strong>: AES-256-CBC encrypted payload</li>
                    </ol>
                </div>

                {/* Important Notes */}
                <h2 className="text-lg font-semibold mb-4">📝 Important Notes</h2>
                <div className="card mb-8">
                    <ul className="space-y-2 text-sm text-gray-400">
                        <li className="flex items-start gap-2">
                            <span className="text-yellow-400">•</span>
                            <span>RSA keys are regenerated on server restart (demo mode)</span>
                        </li>
                        <li className="flex items-start gap-2">
                            <span className="text-yellow-400">•</span>
                            <span>Resources created before restart will show as &quot;tampered&quot;</span>
                        </li>
                        <li className="flex items-start gap-2">
                            <span className="text-yellow-400">•</span>
                            <span>In production, persist keys to maintain resource validity</span>
                        </li>
                        <li className="flex items-start gap-2">
                            <span className="text-yellow-400">•</span>
                            <span>OTPs are displayed in server console (demo mode)</span>
                        </li>
                    </ul>
                </div>

                {/* Testing Instructions */}
                <h2 className="text-lg font-semibold mb-4">🧪 Testing the QP Tamper Detection</h2>
                <div className="card">
                    <ol className="list-decimal list-inside space-y-3 text-sm">
                        <li className="text-gray-300">
                            Upload a question paper from the Faculty Dashboard
                        </li>
                        <li className="text-gray-300">
                            Login as Student and go to Shared Resources
                        </li>
                        <li className="text-gray-300">
                            Click &quot;Verify Integrity&quot; on a question paper
                        </li>
                        <li className="text-gray-300">
                            Click <span className="text-green-400 font-medium">&quot;Validate&quot;</span> - should show <span className="text-green-400">✅ Valid</span>
                        </li>
                        <li className="text-gray-300">
                            Click <span className="text-red-400 font-medium">&quot;Tamper&quot;</span> button to modify the token
                        </li>
                        <li className="text-gray-300">
                            Click <span className="text-green-400 font-medium">&quot;Validate&quot;</span> again - should show <span className="text-red-400">❌ Invalid (tampering detected)</span>
                        </li>
                    </ol>
                </div>
            </main>
        </div>
    );
}
