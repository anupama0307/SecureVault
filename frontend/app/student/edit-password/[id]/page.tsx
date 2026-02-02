'use client';

import { useState, useEffect, use } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { passwordsApi, PasswordEntry } from '@/lib/api';

export default function EditPasswordPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const router = useRouter();
    const [entry, setEntry] = useState<PasswordEntry | null>(null);
    const [siteName, setSiteName] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [generating, setGenerating] = useState(false);

    useEffect(() => {
        const fetchPassword = async () => {
            try {
                const response = await passwordsApi.get(parseInt(id));
                setEntry(response.password);
                setSiteName(response.password.site_name);
                setUsername(response.password.username);
                setPassword(response.password.password);
            } catch (err) {
                setError(err instanceof Error ? err.message : 'Failed to load password');
            } finally {
                setLoading(false);
            }
        };

        fetchPassword();
    }, [id]);

    const handleGenerate = async () => {
        setGenerating(true);
        try {
            const response = await passwordsApi.generate(16);
            setPassword(response.password);
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
        setSaving(true);

        try {
            await passwordsApi.update(parseInt(id), siteName, username, password);
            router.push('/student/vault');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to update password');
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center gradient-bg">
                <div className="spinner" style={{ width: 40, height: 40 }} />
            </div>
        );
    }

    if (!entry) {
        return (
            <div className="min-h-screen flex items-center justify-center gradient-bg">
                <div className="text-center">
                    <div className="text-4xl mb-4">❌</div>
                    <h2 className="text-xl font-semibold mb-2">Password Not Found</h2>
                    <p className="text-gray-500 mb-4">The password entry you&apos;re looking for doesn&apos;t exist.</p>
                    <Link href="/student/vault" className="btn btn-primary">
                        Back to Vault
                    </Link>
                </div>
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
            </div>

            {/* Main Content */}
            <main className="main-with-sidebar">
                <div className="max-w-lg">
                    <Link href="/student/vault" className="inline-flex items-center gap-2 text-gray-500 hover:text-gray-300 mb-6">
                        ← Back to Vault
                    </Link>

                    <div className="card">
                        <h1 className="text-xl font-semibold mb-6 flex items-center gap-3">
                            <span className="text-2xl">✏️</span>
                            Edit Password
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

                            <div className="mb-4">
                                <label className="label">Password</label>
                                <div className="relative">
                                    <input
                                        type={showPassword ? 'text' : 'password'}
                                        className="input pr-24"
                                        placeholder="Enter password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                    />
                                    <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex gap-1">
                                        <button
                                            type="button"
                                            className="p-2 text-gray-500 hover:text-gray-300"
                                            onClick={() => setShowPassword(!showPassword)}
                                        >
                                            {showPassword ? '👁️' : '👁️‍🗨️'}
                                        </button>
                                        <button
                                            type="button"
                                            className="p-2 text-gray-500 hover:text-green-400"
                                            onClick={handleGenerate}
                                            disabled={generating}
                                        >
                                            {generating ? (
                                                <span className="spinner inline-block" style={{ width: 14, height: 14 }} />
                                            ) : (
                                                '🎲'
                                            )}
                                        </button>
                                    </div>
                                </div>
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
                                    disabled={saving}
                                >
                                    {saving ? <span className="spinner" /> : 'Save Changes'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    );
}
