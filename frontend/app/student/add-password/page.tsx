'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { passwordsApi } from '@/lib/api';

export default function AddPasswordPage() {
    const router = useRouter();
    const [siteName, setSiteName] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [useOwn, setUseOwn] = useState(true);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [generating, setGenerating] = useState(false);

    const handleGenerate = async () => {
        setGenerating(true);
        try {
            const response = await passwordsApi.generate(16);
            setPassword(response.password);
            setUseOwn(true);
            setShowPassword(true);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to generate password');
        } finally {
            setGenerating(false);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            await passwordsApi.create(siteName, username, password);
            router.push('/student/vault');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to save password');
        } finally {
            setLoading(false);
        }
    };

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
            </div>

            {/* Main Content */}
            <main className="main-with-sidebar">
                <div className="max-w-lg">
                    {/* Back link */}
                    <Link href="/student/vault" className="inline-flex items-center gap-2 text-gray-500 hover:text-gray-300 mb-6">
                        ← Back to Vault
                    </Link>

                    <div className="card">
                        <h1 className="text-xl font-semibold mb-6 flex items-center gap-3">
                            <span className="text-2xl">➕</span>
                            Add New Password
                        </h1>

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
                                <label className="label">Site/App Name</label>
                                <input
                                    type="text"
                                    className="input"
                                    placeholder="e.g., Gmail, Netflix, Instagram"
                                    value={siteName}
                                    onChange={(e) => setSiteName(e.target.value)}
                                    required
                                />
                            </div>

                            <div className="mb-4">
                                <label className="label">Username / Email</label>
                                <input
                                    type="text"
                                    className="input"
                                    placeholder="Enter username or email"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required
                                />
                            </div>

                            {/* Password Mode Toggle */}
                            <div className="mb-4">
                                <label className="label">Password</label>
                                <div className="flex gap-3 mb-3">
                                    <button
                                        type="button"
                                        onClick={() => setUseOwn(true)}
                                        className={`flex-1 p-3 rounded-lg border-2 transition-all text-sm ${useOwn
                                            ? 'border-blue-500 bg-blue-500/10 text-blue-400'
                                            : 'border-gray-700 text-gray-500 hover:border-gray-600'
                                            }`}
                                    >
                                        🔑 I have a password
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            setUseOwn(false);
                                            handleGenerate();
                                        }}
                                        className={`flex-1 p-3 rounded-lg border-2 transition-all text-sm ${!useOwn
                                            ? 'border-green-500 bg-green-500/10 text-green-400'
                                            : 'border-gray-700 text-gray-500 hover:border-gray-600'
                                            }`}
                                    >
                                        {generating ? (
                                            <span className="spinner inline-block" style={{ width: 16, height: 16 }} />
                                        ) : (
                                            '🎲 Autogenerate'
                                        )}
                                    </button>
                                </div>

                                <div className="relative">
                                    <input
                                        type={showPassword ? 'text' : 'password'}
                                        className="input pr-12"
                                        placeholder="Enter or generate password"
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

                                {!useOwn && password && (
                                    <p className="text-xs text-green-400 mt-2">
                                        ✓ Secure password generated (16 characters)
                                    </p>
                                )}
                            </div>

                            <div className="flex gap-3 mt-6">
                                <Link href="/student/vault" className="flex-1">
                                    <button type="button" className="btn btn-secondary w-full">
                                        Cancel
                                    </button>
                                </Link>
                                <button
                                    type="submit"
                                    className="btn btn-primary flex-1"
                                    disabled={loading}
                                >
                                    {loading ? <span className="spinner" /> : 'Save Password'}
                                </button>
                            </div>
                        </form>

                        <div className="mt-6 p-4 rounded-lg bg-green-500/10 border border-green-500/20">
                            <p className="text-sm text-green-400">
                                🔒 Your password will be encrypted with AES-256 before being stored securely.
                            </p>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}
