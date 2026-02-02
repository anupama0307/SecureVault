'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { passwordsApi, authApi, PasswordEntry } from '@/lib/api';

export default function VaultPage() {
    const router = useRouter();
    const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [copiedId, setCopiedId] = useState<number | null>(null);
    const [deleteModal, setDeleteModal] = useState<{ id: number; name: string } | null>(null);
    const [deleting, setDeleting] = useState(false);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const [user, setUser] = useState<any>(null);

    useEffect(() => {
        // Check auth
        const stored = localStorage.getItem('user');
        if (!stored) {
            router.push('/');
            return;
        }
        const u = JSON.parse(stored);
        if (u.role !== 'student') {
            router.push('/');
            return;
        }
        setUser(u);
        fetchPasswords();
    }, [router]);

    const fetchPasswords = async () => {
        try {
            const response = await passwordsApi.list();
            setPasswords(response.passwords);
        } catch (err) {
            if (err instanceof Error && err.message.includes('expired')) {
                localStorage.clear();
                router.push('/');
            } else {
                setError(err instanceof Error ? err.message : 'Failed to load passwords');
            }
        } finally {
            setLoading(false);
        }
    };

    const handleCopy = async (password: string, id: number) => {
        await navigator.clipboard.writeText(password);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    const handleDelete = async () => {
        if (!deleteModal) return;
        setDeleting(true);
        try {
            await passwordsApi.delete(deleteModal.id);
            setPasswords(passwords.filter((p) => p.id !== deleteModal.id));
            setDeleteModal(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to delete');
        } finally {
            setDeleting(false);
        }
    };

    const filteredPasswords = passwords.filter(
        (p) =>
            p.site_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            p.username.toLowerCase().includes(searchQuery.toLowerCase())
    );

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
        <div className="min-h-screen gradient-bg gradient-student">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-logo">
                    <span>🔐</span>
                    SecureVault
                </div>

                <nav className="sidebar-nav">
                    <li className="sidebar-item">
                        <Link href="/student/vault" className="sidebar-link active">
                            <span>🔑</span>
                            Password Vault
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/student/resources" className="sidebar-link">
                            <span>📚</span>
                            Shared Resources
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
                    <div className="sidebar-user student">
                        <div className="sidebar-username">{user?.username}</div>
                        <div className="sidebar-role">Student</div>
                    </div>
                    <button onClick={handleLogout} className="btn btn-secondary w-full text-sm">
                        Logout
                    </button>
                </div>
            </div>

            {/* Main Content */}
            <main className="main-with-sidebar">
                {/* Header */}
                <div className="page-header">
                    <h1 className="page-title">🔑 Password Vault</h1>
                    <p className="page-subtitle">Create, store, and manage your passwords securely</p>
                </div>

                {/* Stats */}
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-value">{passwords.length}</div>
                        <div className="stat-label">Saved Passwords</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value text-green-500">AES-256</div>
                        <div className="stat-label">Encryption Standard</div>
                    </div>
                </div>

                {error && (
                    <div className="alert alert-error mb-6">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {error}
                    </div>
                )}

                {/* Search */}
                <div className="search-container">
                    <svg className="search-icon w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <input
                        type="text"
                        className="search-input"
                        placeholder="Search passwords..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>

                {/* Password List */}
                {filteredPasswords.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon">🔒</div>
                        <div className="empty-state-title">
                            {searchQuery ? 'No matches found' : 'No passwords saved yet'}
                        </div>
                        <div className="empty-state-text">
                            {searchQuery
                                ? 'Try a different search term'
                                : 'Click the + button to add your first password'}
                        </div>
                    </div>
                ) : (
                    <div>
                        {filteredPasswords.map((entry) => (
                            <div key={entry.id} className="vault-item">
                                <div className="vault-item-icon">
                                    {entry.site_name.charAt(0).toUpperCase()}
                                </div>
                                <div className="vault-item-content">
                                    <div className="vault-item-title">{entry.site_name}</div>
                                    <div className="vault-item-username">{entry.username}</div>
                                </div>
                                <div className="vault-item-actions">
                                    <Link href={`/student/edit-password/${entry.id}`}>
                                        <button className="icon-btn" title="Edit">
                                            ✏️
                                        </button>
                                    </Link>
                                    <button
                                        className="icon-btn delete"
                                        title="Delete"
                                        onClick={() => setDeleteModal({ id: entry.id, name: entry.site_name })}
                                    >
                                        🗑️
                                    </button>
                                    <button
                                        className={`icon-btn ${copiedId === entry.id ? 'text-green-500' : ''}`}
                                        title="Copy password"
                                        onClick={() => handleCopy(entry.password, entry.id)}
                                    >
                                        {copiedId === entry.id ? '✓' : '📋'}
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* FAB - Add Password */}
                <Link href="/student/add-password">
                    <button className="fab" title="Add new password">
                        +
                    </button>
                </Link>

                {/* Delete Confirmation Modal */}
                {deleteModal && (
                    <div className="modal-overlay" onClick={() => setDeleteModal(null)}>
                        <div className="modal" onClick={(e) => e.stopPropagation()}>
                            <div className="text-center mb-4">
                                <span className="text-4xl">🗑️</span>
                            </div>
                            <h3 className="modal-title text-center">Delete Password?</h3>
                            <p className="modal-text text-center">
                                Are you sure you want to delete the password for <strong>{deleteModal.name}</strong>?
                                This action cannot be undone.
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
