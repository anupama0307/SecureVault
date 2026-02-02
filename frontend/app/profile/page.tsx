'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { authApi, User } from '@/lib/api';
import { startRegistration } from '@simplewebauthn/browser';

export default function ProfilePage() {
    const router = useRouter();
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [registering, setRegistering] = useState(false);
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');

    useEffect(() => {
        fetchUser();
    }, []);

    const fetchUser = async () => {
        try {
            const res = await authApi.me();
            setUser(res.user);
        } catch (err) {
            router.push('/');
        } finally {
            setLoading(false);
        }
    };

    const registerPasskey = async () => {
        setMessage('');
        setError('');
        setRegistering(true);

        try {
            // Step 1: Get options from server
            const options = await authApi.webauthn.registerOptions();

            // Step 2: Browser prompts for biometric
            const regResponse = await startRegistration(options);

            // Step 3: Send to server for verification
            const verifyRes = await authApi.webauthn.registerVerify(regResponse);

            if (verifyRes.success) {
                setMessage(verifyRes.message || 'Passkey registered successfully!');
            } else {
                setError('Verification failed. Please try again.');
            }
        } catch (err) {
            const errMsg = err instanceof Error ? err.message : 'Registration failed';
            // Handle user cancellation gracefully
            if (errMsg.includes('cancelled') || errMsg.includes('canceled') || errMsg.includes('NotAllowed')) {
                setError('Registration was cancelled.');
            } else {
                setError(errMsg);
            }
        } finally {
            setRegistering(false);
        }
    };

    const getRoleGradient = (role: string) => {
        switch (role) {
            case 'student': return 'gradient-student';
            case 'faculty': return 'gradient-faculty';
            case 'admin': return 'gradient-admin';
            default: return '';
        }
    };

    const getRoleAccentColor = (role: string) => {
        switch (role) {
            case 'student': return '#3b82f6';
            case 'faculty': return '#8b5cf6';
            case 'admin': return '#f97316';
            default: return '#22c55e';
        }
    };

    const getRoleBgClass = (role: string) => {
        switch (role) {
            case 'student': return 'from-blue-500/20 to-blue-600/5';
            case 'faculty': return 'from-purple-500/20 to-purple-600/5';
            case 'admin': return 'from-orange-500/20 to-orange-600/5';
            default: return 'from-green-500/20 to-green-600/5';
        }
    };

    const getRoleButtonClass = (role: string) => {
        switch (role) {
            case 'student': return 'profile-btn-student';
            case 'faculty': return 'profile-btn-faculty';
            case 'admin': return 'profile-btn-admin';
            default: return '';
        }
    };

    const getBackLink = (role: string) => {
        switch (role) {
            case 'student': return '/student/vault';
            case 'faculty': return '/faculty/dashboard';
            case 'admin': return '/admin/dashboard';
            default: return '/';
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

    const roleColor = getRoleAccentColor(user?.role || '');

    return (
        <div className={`min-h-screen gradient-bg ${getRoleGradient(user?.role || '')}`}>
            {/* Animated Background Orbs */}
            <div className="profile-bg-orbs">
                <div className="profile-orb" style={{ background: roleColor, left: '10%', animationDelay: '0s' }} />
                <div className="profile-orb" style={{ background: roleColor, right: '15%', animationDelay: '2s' }} />
                <div className="profile-orb" style={{ background: roleColor, left: '50%', animationDelay: '4s' }} />
            </div>

            {/* Content */}
            <div className="max-w-4xl mx-auto px-6 py-8 relative z-10">
                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                    <Link
                        href={getBackLink(user?.role || '')}
                        className="profile-back-link"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                        </svg>
                        Back to Dashboard
                    </Link>
                    <button onClick={handleLogout} className="profile-logout-btn">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                        </svg>
                        Sign Out
                    </button>
                </div>

                {/* Main Profile Card */}
                <div className="profile-card">
                    {/* Gradient Border Effect */}
                    <div
                        className="profile-card-glow"
                        style={{ background: `linear-gradient(135deg, ${roleColor}40, transparent, ${roleColor}20)` }}
                    />

                    <div className="profile-card-content">
                        {/* User Avatar Section */}
                        <div className="profile-avatar-section">
                            <div
                                className="profile-avatar-ring"
                                style={{
                                    background: `conic-gradient(from 0deg, ${roleColor}, ${roleColor}50, ${roleColor})`,
                                }}
                            >
                                <div className={`profile-avatar bg-gradient-to-br ${getRoleBgClass(user?.role || '')}`}>
                                    <span className="text-5xl">👤</span>
                                </div>
                            </div>

                            <h1 className="profile-username">{user?.username}</h1>

                            <span
                                className="profile-role-badge"
                                style={{
                                    background: `${roleColor}15`,
                                    color: roleColor,
                                    borderColor: `${roleColor}30`
                                }}
                            >
                                <span className="profile-role-dot" style={{ background: roleColor }} />
                                {user?.role}
                            </span>
                        </div>

                        {/* Divider */}
                        <div className="profile-divider" />

                        {/* Account Info Section */}
                        <div className="profile-info-section">
                            <h2 className="profile-section-title">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                Account Information
                            </h2>
                            <div className="profile-info-grid">
                                <div className="profile-info-item">
                                    <span className="profile-info-label">User ID</span>
                                    <span className="profile-info-value">#{user?.id}</span>
                                </div>
                                <div className="profile-info-item">
                                    <span className="profile-info-label">Role</span>
                                    <span className="profile-info-value capitalize">{user?.role}</span>
                                </div>
                                <div className="profile-info-item">
                                    <span className="profile-info-label">Status</span>
                                    <span className="profile-info-value">
                                        <span className="profile-status-active" />
                                        Active
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* Divider */}
                        <div className="profile-divider" />

                        {/* Passkeys Section */}
                        <div className="profile-passkey-section">
                            <h2 className="profile-section-title">
                                <span className="text-xl">🔑</span>
                                Passkeys & Biometrics
                            </h2>
                            <p className="profile-section-desc">
                                Use your fingerprint, face, or device PIN to log in securely without a password.
                            </p>

                            {message && (
                                <div className="alert alert-success">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                    {message}
                                </div>
                            )}

                            {error && (
                                <div className="alert alert-error">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    {error}
                                </div>
                            )}

                            <button
                                onClick={registerPasskey}
                                disabled={registering}
                                className={`profile-passkey-btn ${getRoleButtonClass(user?.role || '')}`}
                            >
                                {registering ? (
                                    <span className="spinner" />
                                ) : (
                                    <>
                                        <span className="text-lg">👆</span>
                                        Register New Passkey
                                    </>
                                )}
                            </button>

                            {/* Info Box */}
                            <div className="profile-info-box">
                                <h3 className="profile-info-box-title">
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    How it works
                                </h3>
                                <ul className="profile-info-list">
                                    <li>
                                        <span className="profile-info-bullet" style={{ background: roleColor }} />
                                        Your device will prompt for biometric verification
                                    </li>
                                    <li>
                                        <span className="profile-info-bullet" style={{ background: roleColor }} />
                                        A unique cryptographic key is stored on your device
                                    </li>
                                    <li>
                                        <span className="profile-info-bullet" style={{ background: roleColor }} />
                                        Next time, just click &quot;Sign in with Passkey&quot; on the login page
                                    </li>
                                    <li>
                                        <span className="profile-info-bullet" style={{ background: roleColor }} />
                                        No password needed - just your fingerprint or face!
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Security Note */}
                <div className="profile-security-note">
                    <span className="text-lg">🔒</span>
                    <span>Passkeys are more secure than passwords and can&apos;t be phished</span>
                </div>
            </div>
        </div>
    );
}
