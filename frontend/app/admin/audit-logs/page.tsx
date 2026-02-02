'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { adminApi } from '@/lib/api';

interface AuditLog {
    id: number;
    timestamp: string;
    username: string;
    action: string;
    details: string;
    ip_address: string;
}

export default function AuditLogsPage() {
    const router = useRouter();
    const [logs, setLogs] = useState<AuditLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [filterAction, setFilterAction] = useState<string>('all');
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
        fetchLogs();
    }, [router]);

    const fetchLogs = async () => {
        try {
            const response = await adminApi.getAuditLogs(100);
            setLogs(response.logs);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const uniqueActions = [...new Set(logs.map((l) => l.action))];

    const filteredLogs = logs.filter(
        (l) => filterAction === 'all' || l.action === filterAction
    );

    const getActionColor = (action: string) => {
        if (action.includes('FAILED') || action.includes('INVALID')) return 'text-red-400';
        if (action.includes('SUCCESS') || action.includes('CREATED') || action.includes('REGISTERED')) return 'text-green-400';
        if (action.includes('UPLOADED') || action.includes('ACCESSED')) return 'text-blue-400';
        if (action.includes('DELETED')) return 'text-orange-400';
        return 'text-gray-400';
    };

    const formatTimestamp = (timestamp: string) => {
        const date = new Date(timestamp);
        // Format: "Jan 30, 2026 4:46 PM"
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
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
                        <Link href="/admin/dashboard" className="sidebar-link">
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
                        <Link href="/admin/audit-logs" className="sidebar-link active">
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
                <div className="page-header flex items-center justify-between">
                    <div>
                        <h1 className="page-title">📋 Audit Logs</h1>
                        <p className="page-subtitle">Security events and activity tracking</p>
                    </div>
                    <select
                        className="input"
                        style={{ width: 'auto' }}
                        value={filterAction}
                        onChange={(e) => setFilterAction(e.target.value)}
                    >
                        <option value="all">All Actions</option>
                        {uniqueActions.map((action) => (
                            <option key={action} value={action}>
                                {action}
                            </option>
                        ))}
                    </select>
                </div>

                {/* Logs */}
                <div className="card overflow-x-auto">
                    <table className="table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>Action</th>
                                <th>Details</th>
                                <th>IP Address</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredLogs.map((log) => (
                                <tr key={log.id}>
                                    <td className="text-gray-500 text-sm whitespace-nowrap">
                                        {formatTimestamp(log.timestamp)}
                                    </td>
                                    <td className="font-medium">{log.username || '-'}</td>
                                    <td>
                                        <span className={`font-medium ${getActionColor(log.action)}`}>
                                            {log.action}
                                        </span>
                                    </td>
                                    <td className="text-gray-400 text-sm max-w-xs truncate">
                                        {log.details}
                                    </td>
                                    <td className="text-gray-500 font-mono text-sm">
                                        {log.ip_address}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {logs.length === 0 && (
                    <div className="empty-state">
                        <div className="empty-state-icon">📭</div>
                        <div className="empty-state-title">No audit logs yet</div>
                        <div className="empty-state-text">Activity will appear here as users interact with the system</div>
                    </div>
                )}

                {/* Info */}
                <div className="mt-6 p-4 rounded-lg bg-orange-500/10 border border-orange-500/20">
                    <p className="text-sm text-orange-400">
                        🔒 <strong>Security Logging:</strong> All security-relevant events are automatically
                        logged, including login attempts, password changes, resource access, and administrative
                        actions. Logs are retained for security auditing and compliance purposes.
                    </p>
                </div>
            </main>
        </div>
    );
}
