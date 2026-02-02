'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { resourcesApi } from '@/lib/api';

export default function UploadQuizPasswordPage() {
    const router = useRouter();
    const [subject, setSubject] = useState('');
    const [title, setTitle] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            await resourcesApi.uploadQuizPassword(subject, title, password);
            router.push('/faculty/my-uploads');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to upload');
        } finally {
            setLoading(false);
        }
    };

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
                        <Link href="/faculty/upload-quiz" className="sidebar-link active">
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
            </div>

            {/* Main Content */}
            <main className="main-with-sidebar">
                <div className="max-w-lg">
                    <Link href="/faculty/dashboard" className="inline-flex items-center gap-2 text-gray-500 hover:text-gray-300 mb-6">
                        ← Back to Dashboard
                    </Link>

                    <div className="card">
                        <h1 className="text-xl font-semibold mb-6 flex items-center gap-3">
                            <span className="text-2xl">🔑</span>
                            Upload Quiz Password
                        </h1>

                        <p className="text-gray-500 text-sm mb-6">
                            Share quiz access passwords securely with students. The password will be encrypted
                            and digitally signed before storage.
                        </p>

                        {error && (
                            <div className="alert alert-error">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                {error}
                            </div>
                        )}

                        <form onSubmit={handleSubmit}>
                            <div className="mb-4">
                                <label className="label">Subject / Course</label>
                                <input
                                    type="text"
                                    className="input"
                                    placeholder="e.g., 23CSE313 - Foundations of Cyber Security"
                                    value={subject}
                                    onChange={(e) => setSubject(e.target.value)}
                                    required
                                />
                            </div>

                            <div className="mb-4">
                                <label className="label">Quiz Title</label>
                                <input
                                    type="text"
                                    className="input"
                                    placeholder="e.g., Quiz 1 - Encryption Basics"
                                    value={title}
                                    onChange={(e) => setTitle(e.target.value)}
                                    required
                                />
                            </div>

                            <div className="mb-6">
                                <label className="label">Quiz Password</label>
                                <div className="relative">
                                    <input
                                        type={showPassword ? 'text' : 'password'}
                                        className="input pr-12"
                                        placeholder="Enter the quiz access password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                    />
                                    <button
                                        type="button"
                                        className="password-toggle"
                                        onClick={() => setShowPassword(!showPassword)}
                                    >
                                        {showPassword ? '👁️' : '👁️‍🗨️'}
                                    </button>
                                </div>
                            </div>

                            <div className="flex gap-3">
                                <Link href="/faculty/dashboard" className="flex-1">
                                    <button type="button" className="btn btn-secondary w-full">
                                        Cancel
                                    </button>
                                </Link>
                                <button
                                    type="submit"
                                    className="btn btn-primary flex-1"
                                    disabled={loading}
                                >
                                    {loading ? <span className="spinner" /> : 'Upload & Encrypt'}
                                </button>
                            </div>
                        </form>

                        <div className="mt-6 p-4 rounded-lg bg-purple-500/10 border border-purple-500/20">
                            <p className="text-sm text-purple-400">
                                🔒 The password will be encrypted with <strong>AES-256</strong> and signed with
                                <strong> RSA-PSS</strong> for integrity verification.
                            </p>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}
