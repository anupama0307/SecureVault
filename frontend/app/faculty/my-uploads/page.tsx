'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { resourcesApi, Resource } from '@/lib/api';

export default function MyUploadsPage() {
    const router = useRouter();
    const [resources, setResources] = useState<Resource[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [deleteModal, setDeleteModal] = useState<{ id: number; title: string } | null>(null);
    const [deleting, setDeleting] = useState(false);
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
            setError(err instanceof Error ? err.message : 'Failed to load');
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async () => {
        if (!deleteModal) return;
        setDeleting(true);
        try {
            await resourcesApi.delete(deleteModal.id);
            setResources(resources.filter((r) => r.id !== deleteModal.id));
            setDeleteModal(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to delete');
        } finally {
            setDeleting(false);
        }
    };

    const getResourceIcon = (type: string) => {
        switch (type) {
            case 'quiz_password': return '🔑';
            case 'pdf': return '📄';
            case 'question_paper': return '📝';
            default: return '📁';
        }
    };

    const getResourceTypeName = (type: string) => {
        switch (type) {
            case 'quiz_password': return 'Quiz Password';
            case 'pdf': return 'PDF';
            case 'question_paper': return 'Question Paper';
            default: return 'Resource';
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
        <div className="min-h-screen gradient-bg gradient-faculty">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-logo">
                    <span>🔐</span>
                    SecureVault
                </div>

                <nav className="sidebar-nav">
                    <li className="sidebar-item">
                        <Link href="/faculty/dashboard" className="sidebar-link">
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
                        <Link href="/faculty/my-uploads" className="sidebar-link active">
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
                    <h1 className="page-title">📁 My Uploads</h1>
                    <p className="page-subtitle">Manage your encrypted resources</p>
                </div>

                {error && (
                    <div className="alert alert-error mb-6">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {error}
                    </div>
                )}

                {resources.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon">📤</div>
                        <div className="empty-state-title">No uploads yet</div>
                        <div className="empty-state-text">Start by uploading a quiz password, PDF, or question paper</div>
                        <Link href="/faculty/upload-quiz" className="btn btn-primary mt-4 inline-block">
                            Upload Now
                        </Link>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="table">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Title</th>
                                    <th>Subject</th>
                                    <th>Date</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {resources.map((resource) => (
                                    <tr key={resource.id}>
                                        <td>
                                            <span className="text-xl mr-2">{getResourceIcon(resource.resource_type)}</span>
                                            {getResourceTypeName(resource.resource_type)}
                                        </td>
                                        <td className="font-medium">{resource.title}</td>
                                        <td className="text-gray-400">{resource.subject}</td>
                                        <td className="text-gray-500 text-sm">
                                            {new Date(resource.created_at).toLocaleDateString()}
                                        </td>
                                        <td>
                                            <span className="badge badge-success">Encrypted</span>
                                        </td>
                                        <td>
                                            <button
                                                onClick={() => setDeleteModal({ id: resource.id, title: resource.title })}
                                                className="icon-btn delete"
                                                title="Delete"
                                            >
                                                🗑️
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Delete Modal */}
                {deleteModal && (
                    <div className="modal-overlay" onClick={() => setDeleteModal(null)}>
                        <div className="modal" onClick={(e) => e.stopPropagation()}>
                            <div className="text-center mb-4">
                                <span className="text-4xl">🗑️</span>
                            </div>
                            <h3 className="modal-title text-center">Delete Resource?</h3>
                            <p className="modal-text text-center">
                                Are you sure you want to delete <strong>{deleteModal.title}</strong>?
                                Students will no longer be able to access it.
                            </p>
                            <div className="modal-buttons">
                                <button
                                    className="btn btn-secondary flex-1"
                                    onClick={() => setDeleteModal(null)}
                                    disabled={deleting}
                                >
                                    Cancel
                                </button>
                                <button
                                    className="btn btn-danger flex-1"
                                    onClick={handleDelete}
                                    disabled={deleting}
                                >
                                    {deleting ? <span className="spinner" /> : 'Delete'}
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
}
