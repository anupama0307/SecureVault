'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { authApi } from '@/lib/api';

export default function SignupPage() {
    const router = useRouter();
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        role: 'student'
    });
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // Password requirements
    const requirements = {
        length: formData.password.length >= 8,
        uppercase: /[A-Z]/.test(formData.password),
        lowercase: /[a-z]/.test(formData.password),
        special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password),
    };

    const allRequirementsMet = Object.values(requirements).every(Boolean);
    const passwordsMatch = formData.password === formData.confirmPassword && formData.confirmPassword.length > 0;
    const isEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (!allRequirementsMet) {
            setError('Please meet all password requirements');
            return;
        }

        if (!passwordsMatch) {
            setError('Passwords do not match');
            return;
        }

        if (!isEmailValid) {
            setError('Please enter a valid email address');
            return;
        }

        setLoading(true);
        try {
            await authApi.register(formData.username, formData.password, formData.role, formData.email);
            router.push('/?registered=true');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center gradient-bg p-4">
            <div className="card w-full max-w-md">
                {/* Header */}
                <div className="text-center mb-8">
                    <div className="text-4xl mb-4">🔐</div>
                    <h1 className="text-2xl font-bold">Create Account</h1>
                    <p className="text-gray-500 mt-2">Join SecureVault today</p>
                </div>

                {error && (
                    <div className="alert alert-error mb-6">
                        <span>⚠️</span>
                        <span>{error}</span>
                    </div>
                )}

                <form onSubmit={handleSubmit}>
                    {/* Role Selection */}
                    <div className="mb-6">
                        <label className="label">I am a...</label>
                        <div className="grid grid-cols-3 gap-3">
                            {['student', 'faculty', 'admin'].map((role) => (
                                <button
                                    key={role}
                                    type="button"
                                    onClick={() => setFormData({ ...formData, role })}
                                    className={`p-3 rounded-lg border text-center transition-all ${formData.role === role
                                        ? role === 'student'
                                            ? 'border-blue-500 bg-blue-500/10 text-blue-400'
                                            : role === 'faculty'
                                                ? 'border-purple-500 bg-purple-500/10 text-purple-400'
                                                : 'border-orange-500 bg-orange-500/10 text-orange-400'
                                        : 'border-gray-700 text-gray-500 hover:border-gray-600'
                                        }`}
                                >
                                    <div className="text-xl mb-1">
                                        {role === 'student' ? '🎓' : role === 'faculty' ? '👨‍🏫' : '👑'}
                                    </div>
                                    <div className="text-sm capitalize">{role}</div>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Username */}
                    <div className="mb-4">
                        <label className="label">Username</label>
                        <input
                            type="text"
                            className="input"
                            placeholder="Choose a username"
                            value={formData.username}
                            onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                            required
                        />
                    </div>

                    {/* Email */}
                    <div className="mb-6">
                        <label className="label">Email Address</label>
                        <input
                            type="email"
                            className="input"
                            placeholder="name@example.com"
                            value={formData.email}
                            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                            required
                        />
                    </div>

                    {/* Password */}
                    <div className="mb-4">
                        <label className="label">Password</label>
                        <div className="relative">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                className="input pr-12"
                                placeholder="Create a strong password"
                                value={formData.password}
                                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                                required
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="password-toggle"
                            >
                                {showPassword ? '🙈' : '👁️'}
                            </button>
                        </div>
                    </div>

                    {/* Password Requirements */}
                    <div className="mb-6 p-4 rounded-lg bg-black/30 border border-gray-800">
                        <div className="text-xs text-gray-500 mb-3">PASSWORD REQUIREMENTS (NIST SP 800-63-2)</div>
                        <div className="space-y-2">
                            <div className={`requirement ${requirements.length ? 'met' : ''}`}>
                                <div className={`requirement-icon ${requirements.length ? 'met' : 'pending'}`}>
                                    {requirements.length ? '✓' : ''}
                                </div>
                                <span>At least 8 characters</span>
                            </div>
                            <div className={`requirement ${requirements.uppercase ? 'met' : ''}`}>
                                <div className={`requirement-icon ${requirements.uppercase ? 'met' : 'pending'}`}>
                                    {requirements.uppercase ? '✓' : ''}
                                </div>
                                <span>One uppercase letter</span>
                            </div>
                            <div className={`requirement ${requirements.lowercase ? 'met' : ''}`}>
                                <div className={`requirement-icon ${requirements.lowercase ? 'met' : 'pending'}`}>
                                    {requirements.lowercase ? '✓' : ''}
                                </div>
                                <span>One lowercase letter</span>
                            </div>
                            <div className={`requirement ${requirements.special ? 'met' : ''}`}>
                                <div className={`requirement-icon ${requirements.special ? 'met' : 'pending'}`}>
                                    {requirements.special ? '✓' : ''}
                                </div>
                                <span>One special character</span>
                            </div>
                        </div>
                    </div>

                    {/* Confirm Password */}
                    <div className="mb-6">
                        <label className="label">Confirm Password</label>
                        <input
                            type="password"
                            className="input"
                            placeholder="Confirm your password"
                            value={formData.confirmPassword}
                            onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                            required
                        />
                        {formData.confirmPassword && (
                            <div className={`mt-2 text-sm ${passwordsMatch ? 'text-green-400' : 'text-red-400'}`}>
                                {passwordsMatch ? '✓ Passwords match' : '✗ Passwords do not match'}
                            </div>
                        )}
                    </div>

                    {/* Submit */}
                    <button
                        type="submit"
                        disabled={loading || !allRequirementsMet || !passwordsMatch || !isEmailValid}
                        className="btn btn-primary w-full mb-4"
                    >
                        {loading ? (
                            <span className="spinner" />
                        ) : (
                            'Create Account'
                        )}
                    </button>
                </form>

                {/* Footer */}
                <p className="text-center text-gray-500 text-sm">
                    Already have an account?{' '}
                    <Link href="/" className="text-green-400 hover:underline">
                        Sign in
                    </Link>
                </p>
            </div>
        </div>
    );
}
