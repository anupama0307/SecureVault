'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { authApi, validatePassword } from '@/lib/api';

type Step = 'username' | 'otp' | 'newPassword';

export default function ResetPasswordPage() {
    const router = useRouter();
    const [step, setStep] = useState<Step>('username');
    const [username, setUsername] = useState('');
    const [otp, setOtp] = useState(['', '', '', '', '', '']);
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [loading, setLoading] = useState(false);
    const [timer, setTimer] = useState(300);
    const otpRefs = useRef<(HTMLInputElement | null)[]>([]);

    // Password validation
    const [passwordChecks, setPasswordChecks] = useState({
        length: false,
        uppercase: false,
        lowercase: false,
        special: false,
    });

    useEffect(() => {
        setPasswordChecks({
            length: newPassword.length >= 8,
            uppercase: /[A-Z]/.test(newPassword),
            lowercase: /[a-z]/.test(newPassword),
            special: /[!@#$%^&*]/.test(newPassword),
        });
    }, [newPassword]);

    const allChecksPass = Object.values(passwordChecks).every(Boolean);

    // Timer countdown
    useEffect(() => {
        if (step === 'otp' && timer > 0) {
            const interval = setInterval(() => {
                setTimer((t) => t - 1);
            }, 1000);
            return () => clearInterval(interval);
        }
    }, [step, timer]);

    const formatTime = (seconds: number) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    };

    const handleUsernameSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            await authApi.forgotPassword(username);
            setStep('otp');
            setTimer(300);
            setTimeout(() => otpRefs.current[0]?.focus(), 100);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to send OTP');
        } finally {
            setLoading(false);
        }
    };

    const handleOtpChange = (index: number, value: string) => {
        if (value.length > 1) return;

        const newOtp = [...otp];
        newOtp[index] = value;
        setOtp(newOtp);

        if (value && index < 5) {
            otpRefs.current[index + 1]?.focus();
        }
    };

    const handleOtpKeyDown = (index: number, e: React.KeyboardEvent) => {
        if (e.key === 'Backspace' && !otp[index] && index > 0) {
            otpRefs.current[index - 1]?.focus();
        }
    };

    const handleOtpSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        const otpCode = otp.join('');
        if (otpCode.length !== 6) {
            setError('Please enter the complete 6-digit OTP');
            return;
        }
        setStep('newPassword');
    };

    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        const validation = validatePassword(newPassword);
        if (!validation.isValid) {
            setError('Password does not meet requirements');
            return;
        }

        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        setLoading(true);

        try {
            const otpCode = otp.join('');
            const response = await authApi.resetPassword(username, otpCode, newPassword);
            if (response.success) {
                setSuccess('Password reset successfully! Redirecting to login...');
                setTimeout(() => router.push('/'), 2000);
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to reset password');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center gradient-bg p-4">
            <div className="w-full max-w-md">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-green-500/20 to-green-600/10 mb-4">
                        <span className="text-3xl">🔐</span>
                    </div>
                    <h1 className="text-2xl font-bold text-white">Reset Password</h1>
                    <p className="text-gray-500 text-sm mt-1">
                        {step === 'username' && 'Enter your username to receive a reset code'}
                        {step === 'otp' && 'Enter the OTP from the server console'}
                        {step === 'newPassword' && 'Create your new password'}
                    </p>
                </div>

                {/* Progress Steps */}
                <div className="flex items-center justify-center gap-2 mb-8">
                    {['username', 'otp', 'newPassword'].map((s, i) => (
                        <div key={s} className="flex items-center">
                            <div
                                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium
                  ${step === s || ['username', 'otp', 'newPassword'].indexOf(step) > i
                                        ? 'bg-green-500 text-white'
                                        : 'bg-gray-800 text-gray-500'
                                    }`}
                            >
                                {i + 1}
                            </div>
                            {i < 2 && (
                                <div
                                    className={`w-12 h-0.5 ${['username', 'otp', 'newPassword'].indexOf(step) > i
                                            ? 'bg-green-500'
                                            : 'bg-gray-800'
                                        }`}
                                />
                            )}
                        </div>
                    ))}
                </div>

                {/* Card */}
                <div className="card">
                    {error && (
                        <div className="alert alert-error">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            {error}
                        </div>
                    )}

                    {success && (
                        <div className="alert alert-success">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            {success}
                        </div>
                    )}

                    {/* Step 1: Username */}
                    {step === 'username' && (
                        <form onSubmit={handleUsernameSubmit}>
                            <div className="mb-6">
                                <label className="label">Username</label>
                                <input
                                    type="text"
                                    className="input"
                                    placeholder="Enter your username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required
                                    autoFocus
                                />
                            </div>

                            <button
                                type="submit"
                                className="btn btn-primary w-full"
                                disabled={loading}
                            >
                                {loading ? <span className="spinner" /> : 'Send Reset Code'}
                            </button>
                        </form>
                    )}

                    {/* Step 2: OTP */}
                    {step === 'otp' && (
                        <form onSubmit={handleOtpSubmit}>
                            <div className="flex justify-center gap-3 mb-6">
                                {otp.map((digit, index) => (
                                    <input
                                        key={index}
                                        ref={(el) => { otpRefs.current[index] = el; }}
                                        type="text"
                                        inputMode="numeric"
                                        maxLength={1}
                                        className="otp-input"
                                        value={digit}
                                        onChange={(e) => handleOtpChange(index, e.target.value.replace(/\D/g, ''))}
                                        onKeyDown={(e) => handleOtpKeyDown(index, e)}
                                    />
                                ))}
                            </div>

                            <div className="timer mb-6">
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <span>Code expires in</span>
                                <span className="timer-value">{formatTime(timer)}</span>
                            </div>

                            <button
                                type="submit"
                                className="btn btn-primary w-full"
                                disabled={timer === 0}
                            >
                                {timer === 0 ? 'OTP Expired' : 'Verify Code'}
                            </button>

                            <div className="mt-4 p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
                                <p className="text-sm text-blue-400">
                                    💡 Check the backend server console for the OTP code.
                                </p>
                            </div>
                        </form>
                    )}

                    {/* Step 3: New Password */}
                    {step === 'newPassword' && (
                        <form onSubmit={handlePasswordSubmit}>
                            <div className="mb-4">
                                <label className="label">New Password</label>
                                <div className="relative">
                                    <input
                                        type={showPassword ? 'text' : 'password'}
                                        className="input pr-12"
                                        placeholder="Enter new password"
                                        value={newPassword}
                                        onChange={(e) => setNewPassword(e.target.value)}
                                        required
                                        autoFocus
                                    />
                                    <button
                                        type="button"
                                        className="password-toggle"
                                        onClick={() => setShowPassword(!showPassword)}
                                    >
                                        {showPassword ? '👁️' : '👁️‍🗨️'}
                                    </button>
                                </div>

                                {/* Password Requirements */}
                                <div className="mt-3 space-y-1">
                                    <div className={`requirement ${passwordChecks.length ? 'met' : ''}`}>
                                        <span className={`requirement-icon ${passwordChecks.length ? 'met' : 'pending'}`}>
                                            {passwordChecks.length ? '✓' : ''}
                                        </span>
                                        At least 8 characters
                                    </div>
                                    <div className={`requirement ${passwordChecks.uppercase ? 'met' : ''}`}>
                                        <span className={`requirement-icon ${passwordChecks.uppercase ? 'met' : 'pending'}`}>
                                            {passwordChecks.uppercase ? '✓' : ''}
                                        </span>
                                        One uppercase letter (A-Z)
                                    </div>
                                    <div className={`requirement ${passwordChecks.lowercase ? 'met' : ''}`}>
                                        <span className={`requirement-icon ${passwordChecks.lowercase ? 'met' : 'pending'}`}>
                                            {passwordChecks.lowercase ? '✓' : ''}
                                        </span>
                                        One lowercase letter (a-z)
                                    </div>
                                    <div className={`requirement ${passwordChecks.special ? 'met' : ''}`}>
                                        <span className={`requirement-icon ${passwordChecks.special ? 'met' : 'pending'}`}>
                                            {passwordChecks.special ? '✓' : ''}
                                        </span>
                                        One special character (!@#$%^&*)
                                    </div>
                                </div>
                            </div>

                            <div className="mb-6">
                                <label className="label">Confirm New Password</label>
                                <input
                                    type="password"
                                    className="input"
                                    placeholder="Confirm new password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                />
                                {confirmPassword && newPassword !== confirmPassword && (
                                    <p className="text-red-400 text-xs mt-1">Passwords do not match</p>
                                )}
                            </div>

                            <button
                                type="submit"
                                className="btn btn-primary w-full"
                                disabled={loading || !allChecksPass || newPassword !== confirmPassword}
                            >
                                {loading ? <span className="spinner" /> : 'Reset Password'}
                            </button>
                        </form>
                    )}

                    <div className="mt-6 pt-4 border-t border-gray-800 text-center text-sm text-gray-500">
                        Remember your password?{' '}
                        <Link href="/" className="text-green-500 hover:text-green-400">
                            Back to login
                        </Link>
                    </div>
                </div>
            </div>
        </div>
    );
}
