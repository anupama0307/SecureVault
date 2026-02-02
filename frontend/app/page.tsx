'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { authApi } from '@/lib/api';

import { startAuthentication } from '@simplewebauthn/browser';

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<'credentials' | 'otp'>('credentials');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [timer, setTimer] = useState(300); // 5 minutes
  const otpRefs = useRef<(HTMLInputElement | null)[]>([]);

  // OTP timer countdown
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

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await authApi.login(username, password);
      if (response.requires_otp) {
        setStep('otp');
        setTimer(300);
        setTimeout(() => otpRefs.current[0]?.focus(), 100);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    if (!username) {
      setError('Please enter your username first');
      return;
    }
    setError('');
    setLoading(true);

    try {
      const options = await authApi.webauthn.loginOptions(username);
      const authResponse = await startAuthentication(options);
      const verifyRes = await authApi.webauthn.loginVerify(username, authResponse);

      if (verifyRes.success && verifyRes.token) {
        localStorage.setItem('token', verifyRes.token);
        localStorage.setItem('user', JSON.stringify(verifyRes.user));

        switch (verifyRes.user.role) {
          case 'admin': router.push('/admin/dashboard'); break;
          case 'faculty': router.push('/faculty/dashboard'); break;
          default: router.push('/student/vault');
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (value.length > 1) return;

    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    // Auto-focus next input
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
    setError('');
    setLoading(true);

    const otpCode = otp.join('');
    if (otpCode.length !== 6) {
      setError('Please enter the complete 6-digit OTP');
      setLoading(false);
      return;
    }

    try {
      const response = await authApi.verifyOtp(username, otpCode);
      if (response.success && response.token) {
        localStorage.setItem('token', response.token);
        localStorage.setItem('user', JSON.stringify(response.user));

        // Redirect based on role
        switch (response.user.role) {
          case 'admin':
            router.push('/admin/dashboard');
            break;
          case 'faculty':
            router.push('/faculty/dashboard');
            break;
          default:
            router.push('/student/vault');
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid OTP');
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
          <h1 className="text-2xl font-bold text-white">SecureVault</h1>
          <p className="text-gray-500 text-sm mt-1">Academic Password Manager</p>
        </div>

        {/* Card */}
        <div className="card">
          {step === 'credentials' ? (
            <>
              <h2 className="text-xl font-semibold mb-6 text-center">Welcome Back</h2>

              {error && (
                <div className="alert alert-error">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {error}
                </div>
              )}

              <form onSubmit={handleCredentialsSubmit}>
                <div className="mb-4">
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

                <div className="mb-6">
                  <label className="label">Password</label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      className="input pr-12"
                      placeholder="Enter your password"
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

                <button
                  type="button"
                  onClick={handlePasskeyLogin}
                  className="btn btn-outline w-full mb-3 group border-green-500/30 text-green-400 hover:bg-green-500/10 hover:border-green-500"
                  disabled={loading}
                >
                  <span className="mr-2 group-hover:scale-110 transition-transform inline-block">👆</span>
                  Sign in with Passkey
                </button>

                <div className="relative flex py-2 items-center">
                  <div className="flex-grow border-t border-gray-800"></div>
                  <span className="flex-shrink mx-4 text-gray-500 text-xs">OR WITH PASSWORD</span>
                  <div className="flex-grow border-t border-gray-800"></div>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary w-full"
                  disabled={loading}
                >
                  {loading ? (
                    <span className="spinner" />
                  ) : (
                    'Login with Password'
                  )}
                </button>
              </form>

              <div className="mt-6 text-center text-sm">
                <Link href="/reset-password" className="text-green-500 hover:text-green-400">
                  Forgot password?
                </Link>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-800 text-center text-sm text-gray-500">
                Don&apos;t have an account?{' '}
                <Link href="/signup" className="text-green-500 hover:text-green-400">
                  Create account
                </Link>
              </div>
            </>
          ) : (
            <>
              <div className="text-center mb-6">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-green-500/10 mb-4">
                  <span className="text-2xl">🔑</span>
                </div>
                <h2 className="text-xl font-semibold">Verify Your Identity</h2>
                <p className="text-gray-500 text-sm mt-2">
                  Enter the 6-digit code from the server console
                </p>
              </div>

              {error && (
                <div className="alert alert-error">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {error}
                </div>
              )}

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
                  disabled={loading || timer === 0}
                >
                  {loading ? (
                    <span className="spinner" />
                  ) : timer === 0 ? (
                    'OTP Expired'
                  ) : (
                    'Verify OTP'
                  )}
                </button>
              </form>

              <button
                type="button"
                className="btn btn-secondary w-full mt-3"
                onClick={() => {
                  setStep('credentials');
                  setOtp(['', '', '', '', '', '']);
                  setError('');
                }}
              >
                Back to Login
              </button>

              <div className="mt-6 p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <p className="text-sm text-blue-400">
                  💡 <strong>Hint:</strong> Check the backend server console for the OTP code.
                  This simulates SMS/Email delivery in demo mode.
                </p>
              </div>
            </>
          )}
        </div>

        {/* Demo accounts info */}
        <div className="mt-6 text-center text-xs text-gray-600">
          <p className="mb-2">Demo Accounts:</p>
          <p>admin / admin123 • faculty1 / faculty123 • student1 / student123</p>
        </div>
      </div>
    </div>
  );
}
