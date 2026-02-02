'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { adminApi } from '@/lib/api';

interface User {
    id: number;
    username: string;
    role: string;
    created_at: string;
}

export default function UsersPage() {
    const router = useRouter();
    const [users, setUsers] = useState<User[]>([]);
    const [byRole, setByRole] = useState<{ students: number; faculty: number; admins: number }>({
        students: 0,
        faculty: 0,
        admins: 0
    });
    const [loading, setLoading] = useState(true);
    const [filterRole, setFilterRole] = useState<string>('all');
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
        fetchUsers();
    }, [router]);

    const fetchUsers = async () => {
        try {
            const response = await adminApi.getUsers();
            setUsers(response.users);
            setByRole(response.by_role);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const filteredUsers = users.filter(
        (u) => filterRole === 'all' || u.role === filterRole
    );

    const getRoleBadge = (role: string) => {
        switch (role) {
            case 'student':
                return 'badge-student';
            case 'faculty':
                return 'badge-faculty';
            case 'admin':
                return 'badge-admin';
            default:
                return '';
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
                        <Link href="/admin/dashboard" className="sidebar-link">
                            <span>📊</span>
                            Dashboard
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/admin/users" className="sidebar-link active">
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
                    <h1 className="page-title">👥 User Management</h1>
                    <p className="page-subtitle">View and manage all system users</p>
                </div>

                {/* Stats */}
                <div className="stats-grid mb-8">
                    <div
                        className={`stat-card cursor-pointer ${filterRole === 'all' ? 'ring-2 ring-orange-500' : ''}`}
                        onClick={() => setFilterRole('all')}
                    >
                        <div className="stat-value">{users.length}</div>
                        <div className="stat-label">All Users</div>
                    </div>
                    <div
                        className={`stat-card cursor-pointer ${filterRole === 'student' ? 'ring-2 ring-blue-500' : ''}`}
                        onClick={() => setFilterRole('student')}
                    >
                        <div className="stat-value text-blue-400">{byRole.students}</div>
                        <div className="stat-label">Students</div>
                    </div>
                    <div
                        className={`stat-card cursor-pointer ${filterRole === 'faculty' ? 'ring-2 ring-purple-500' : ''}`}
                        onClick={() => setFilterRole('faculty')}
                    >
                        <div className="stat-value text-purple-400">{byRole.faculty}</div>
                        <div className="stat-label">Faculty</div>
                    </div>
                    <div
                        className={`stat-card cursor-pointer ${filterRole === 'admin' ? 'ring-2 ring-orange-500' : ''}`}
                        onClick={() => setFilterRole('admin')}
                    >
                        <div className="stat-value text-orange-400">{byRole.admins}</div>
                        <div className="stat-label">Admins</div>
                    </div>
                </div>

                {/* User Table */}
                <div className="card overflow-x-auto">
                    <table className="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Role</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredUsers.map((u) => (
                                <tr key={u.id}>
                                    <td className="text-gray-500">#{u.id}</td>
                                    <td className="font-medium">{u.username}</td>
                                    <td>
                                        <span className={`badge ${getRoleBadge(u.role)}`}>
                                            {u.role.charAt(0).toUpperCase() + u.role.slice(1)}
                                        </span>
                                    </td>
                                    <td className="text-gray-500 text-sm">
                                        {new Date(u.created_at).toLocaleDateString()}{' '}
                                        {new Date(u.created_at).toLocaleTimeString()}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </main>
        </div>
    );
}
