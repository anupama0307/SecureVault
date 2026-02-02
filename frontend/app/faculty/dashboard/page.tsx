'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { resourcesApi, Resource, adminApi } from '@/lib/api';

export default function FacultyDashboard() {
    const router = useRouter();
    const [resources, setResources] = useState<Resource[]>([]);
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
        if (u.role !== 'faculty') {
            router.push('/');
            return;
        }
        setUser(u);
        fetchResources();
    }, [router]);

    const fetchResources = async () => {
        try {
            const response = await resourcesApi.getMyUploads();
            setResources(response.resources);
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

    const quizCount = resources.filter(r => r.resource_type === 'quiz_password').length;
    const pdfCount = resources.filter(r => r.resource_type === 'pdf').length;
    const qpCount = resources.filter(r => r.resource_type === 'question_paper').length;

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center gradient-bg">
                <div className="spinner" style={{ width: 40, height: 40 }} />
            </div>
        );
    }

    return (
        <div className="min-h-screen gradient-bg gradient-faculty">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-logo">
                    <span>🔐</span>
                    SecureVault
                </div>

                <nav className="sidebar-nav">
                    <li className="sidebar-item">
                        <Link href="/faculty/dashboard" className="sidebar-link active">
                            <span>📊</span>
                            Dashboard
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/faculty/upload-quiz" className="sidebar-link">
                            <span>🔑</span>
                            Upload Quiz Password
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/faculty/upload-pdf" className="sidebar-link">
                            <span>📄</span>
                            Upload PDF
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/faculty/upload-qp" className="sidebar-link">
                            <span>📝</span>
                            Upload Question Paper
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/faculty/my-uploads" className="sidebar-link">
                            <span>📁</span>
                            My Uploads
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
                    <div className="sidebar-user faculty">
                        <div className="sidebar-username">{user?.username}</div>
                        <div className="sidebar-role">Faculty</div>
                    </div>
                    <button onClick={handleLogout} className="btn btn-secondary w-full text-sm">
                        Logout
                    </button>
                </div>
            </div>

            {/* Main Content */}
            <main className="main-with-sidebar">
                <div className="page-header">
                    <h1 className="page-title">👨‍🏫 Faculty Dashboard</h1>
                    <p className="page-subtitle">Manage your encrypted academic resources</p>
                </div>

                {/* Stats */}
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-value">{resources.length}</div>
                        <div className="stat-label">Total Uploads</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value text-purple-400">{quizCount}</div>
                        <div className="stat-label">Quiz Passwords</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value text-blue-400">{pdfCount}</div>
                        <div className="stat-label">PDFs</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value text-green-400">{qpCount}</div>
                        <div className="stat-label">Question Papers</div>
                    </div>
                </div>

                {/* Quick Actions */}
                <h2 className="text-lg font-semibold mb-4">Quick Actions</h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                    <Link href="/faculty/upload-quiz">
                        <div className="card card-hover cursor-pointer">
                            <span className="text-3xl mb-3 block">🔑</span>
                            <h3 className="font-medium mb-1">Upload Quiz Password</h3>
                            <p className="text-sm text-gray-500">Share access passwords for AUMS quizzes</p>
                        </div>
                    </Link>
                    <Link href="/faculty/upload-pdf">
                        <div className="card card-hover cursor-pointer">
                            <span className="text-3xl mb-3 block">📄</span>
                            <h3 className="font-medium mb-1">Upload PDF</h3>
                            <p className="text-sm text-gray-500">Share encrypted lecture notes & resources</p>
                        </div>
                    </Link>
                    <Link href="/faculty/upload-qp">
                        <div className="card card-hover cursor-pointer">
                            <span className="text-3xl mb-3 block">📝</span>
                            <h3 className="font-medium mb-1">Upload Question Paper</h3>
                            <p className="text-sm text-gray-500">Share signed & encrypted exam papers</p>
                        </div>
                    </Link>
                </div>

                {/* Recent Uploads */}
                <h2 className="text-lg font-semibold mb-4">Recent Uploads</h2>
                {resources.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon">📤</div>
                        <div className="empty-state-title">No uploads yet</div>
                        <div className="empty-state-text">Start by uploading a quiz password or PDF</div>
                    </div>
                ) : (
                    <div className="grid gap-3">
                        {resources.slice(0, 5).map((resource) => (
                            <div key={resource.id} className="card flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <span className="text-xl">
                                        {resource.resource_type === 'quiz_password' ? '🔑' :
                                            resource.resource_type === 'pdf' ? '📄' : '📝'}
                                    </span>
                                    <div>
                                        <h4 className="font-medium">{resource.title}</h4>
                                        <p className="text-sm text-gray-500">{resource.subject}</p>
                                    </div>
                                </div>
                                <span className="badge badge-success">Encrypted</span>
                            </div>
                        ))}
                    </div>
                )}

                {/* Security Info */}
                <div className="mt-8 p-4 rounded-lg bg-purple-500/10 border border-purple-500/20">
                    <p className="text-sm text-purple-400">
                        🔒 <strong>Security Features:</strong> All uploads are automatically encrypted with AES-256
                        and digitally signed with RSA-PSS to ensure integrity. Students can only decrypt and view
                        resources - they cannot modify or delete them.
                    </p>
                </div>
            </main>
        </div>
    );
}
