'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { resourcesApi, Resource } from '@/lib/api';

interface TokenData {
    token: string;
    resourceId: number;
    title: string;
    isValid: boolean | null;
    validationMessage: string;
}

export default function StudentResourcesPage() {
    const router = useRouter();
    const [resources, setResources] = useState<Resource[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [decrypting, setDecrypting] = useState<number | null>(null);
    const [decryptedContent, setDecryptedContent] = useState<{ id: number; content: string; type: string } | null>(null);
    const [tokenData, setTokenData] = useState<TokenData | null>(null);
    const [loadingToken, setLoadingToken] = useState<number | null>(null);
    const [validating, setValidating] = useState(false);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const [user, setUser] = useState<any>(null);

    useEffect(() => {
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
        fetchResources();
    }, [router]);

    const fetchResources = async () => {
        try {
            const response = await resourcesApi.getShared();
            setResources(response.resources);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load resources');
        } finally {
            setLoading(false);
        }
    };

    const handleDecrypt = async (id: number) => {
        setDecrypting(id);
        try {
            const response = await resourcesApi.decrypt(id);
            if (response.success) {
                if (response.content) {
                    setDecryptedContent({ id, content: response.content, type: response.resource_type });
                } else if (response.file_data) {
                    // Handle file download
                    const blob = new Blob([Uint8Array.from(atob(response.file_data), c => c.charCodeAt(0))], { type: 'application/pdf' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${response.title}.pdf`;
                    a.click();
                    URL.revokeObjectURL(url);
                }
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to decrypt');
        } finally {
            setDecrypting(null);
        }
    };

    const handleViewToken = async (id: number, title: string) => {
        setLoadingToken(id);
        try {
            const response = await resourcesApi.getToken(id);
            if (response.success) {
                setTokenData({
                    token: response.token,
                    resourceId: id,
                    title: title,
                    isValid: null,
                    validationMessage: '',
                });
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to get token');
        } finally {
            setLoadingToken(null);
        }
    };

    const handleValidateToken = async () => {
        if (!tokenData) return;
        setValidating(true);
        try {
            const response = await resourcesApi.verifyToken(tokenData.resourceId, tokenData.token);
            setTokenData({
                ...tokenData,
                isValid: response.valid,
                validationMessage: response.message,
            });
        } catch (err) {
            setTokenData({
                ...tokenData,
                isValid: false,
                validationMessage: 'Verification failed',
            });
        } finally {
            setValidating(false);
        }
    };

    const handleTamperToken = () => {
        if (!tokenData) return;
        // Corrupt the token by modifying the ciphertext
        const parts = tokenData.token.split('|');
        if (parts.length === 3) {
            // Modify the ciphertext part to simulate tampering
            const tamperedCiphertext = parts[2].slice(0, -5) + 'XXXXX';
            const tamperedToken = `${parts[0]}|${parts[1]}|${tamperedCiphertext}`;
            setTokenData({
                ...tokenData,
                token: tamperedToken,
                isValid: null,
                validationMessage: '⚠️ Token has been modified! Click Validate to detect tampering.',
            });
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
            case 'pdf': return 'PDF Document';
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
        <div className="min-h-screen gradient-bg gradient-student">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-logo">
                    <span>🔐</span>
                    SecureVault
                </div>

                <nav className="sidebar-nav">
                    <li className="sidebar-item">
                        <Link href="/student/vault" className="sidebar-link">
                            <span>🔑</span>
                            Password Vault
                        </Link>
                    </li>
                    <li className="sidebar-item">
                        <Link href="/student/resources" className="sidebar-link active">
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
                <div className="page-header">
                    <h1 className="page-title">📚 Shared Resources</h1>
                    <p className="page-subtitle">Access faculty-shared quiz passwords, PDFs, and question papers</p>
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
                        <div className="empty-state-icon">📭</div>
                        <div className="empty-state-title">No resources available</div>
                        <div className="empty-state-text">Faculty haven&apos;t shared any resources yet.</div>
                    </div>
                ) : (
                    <div className="grid gap-4">
                        {resources.map((resource) => (
                            <div key={resource.id} className="card card-hover">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className="w-12 h-12 rounded-xl bg-purple-500/10 flex items-center justify-center text-2xl">
                                            {getResourceIcon(resource.resource_type)}
                                        </div>
                                        <div>
                                            <h3 className="font-medium text-white">{resource.title}</h3>
                                            <div className="flex items-center gap-3 mt-1">
                                                <span className="text-sm text-gray-500">{resource.subject}</span>
                                                <span className="badge badge-faculty text-xs">{getResourceTypeName(resource.resource_type)}</span>
                                            </div>
                                            <p className="text-xs text-gray-600 mt-1">
                                                By {resource.faculty_name} • {new Date(resource.created_at).toLocaleDateString()}
                                            </p>
                                        </div>
                                    </div>
                                    <div className="flex gap-2">
                                        {/* Show Token button for Question Papers */}
                                        {resource.resource_type === 'question_paper' && (
                                            <button
                                                onClick={() => handleViewToken(resource.id, resource.title)}
                                                disabled={loadingToken === resource.id}
                                                className="btn btn-secondary"
                                                title="QP Tamper Detection"
                                            >
                                                {loadingToken === resource.id ? (
                                                    <span className="spinner" />
                                                ) : (
                                                    '🔍 VERIFY INTEGRITY'
                                                )}
                                            </button>
                                        )}
                                        <button
                                            onClick={() => handleDecrypt(resource.id)}
                                            disabled={decrypting === resource.id}
                                            className="btn btn-primary"
                                        >
                                            {decrypting === resource.id ? (
                                                <span className="spinner" />
                                            ) : resource.resource_type === 'quiz_password' ? (
                                                '🔓 REVEAL'
                                            ) : (
                                                '📥 DOWNLOAD'
                                            )}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Token Verification Modal (QP Tamper Detection) */}
                {tokenData && (
                    <div className="modal-overlay" onClick={() => setTokenData(null)}>
                        <div className="modal" style={{ maxWidth: '600px' }} onClick={(e) => e.stopPropagation()}>
                            <div className="text-center mb-4">
                                <span className="text-4xl">🛡️</span>
                            </div>
                            <h3 className="modal-title text-center">QP Tamper Detection</h3>
                            <p className="text-sm text-gray-500 text-center mb-4">
                                Digital signature verification for: <strong>{tokenData.title}</strong>
                            </p>

                            {/* Token Format Info */}
                            <div className="p-3 bg-gray-900/50 rounded-lg border border-gray-700 mb-4">
                                <div className="text-xs text-gray-500 mb-2">TOKEN FORMAT</div>
                                <code className="text-xs text-blue-400">
                                    Base64( IV[16 bytes] + Signature[256 bytes] + Ciphertext )
                                </code>
                            </div>

                            {/* Token Display */}
                            <div className="mb-4">
                                <label className="text-xs text-gray-500 block mb-2">ENCRYPTED & SIGNED TOKEN</label>
                                <div className="p-3 bg-gray-900 rounded-lg border border-gray-700 max-h-32 overflow-y-auto">
                                    <code className="text-xs text-green-400 font-mono break-all">
                                        {tokenData.token.substring(0, 200)}...
                                    </code>
                                </div>
                            </div>

                            {/* Validation Status */}
                            {tokenData.validationMessage && (
                                <div className={`p-4 rounded-lg border mb-4 ${tokenData.isValid === true
                                    ? 'bg-green-500/10 border-green-500/30 text-green-400'
                                    : tokenData.isValid === false
                                        ? 'bg-red-500/10 border-red-500/30 text-red-400'
                                        : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
                                    }`}>
                                    <div className="font-medium text-center">
                                        {tokenData.validationMessage}
                                    </div>
                                </div>
                            )}

                            {/* Action Buttons */}
                            <div className="flex gap-3 mb-4">
                                <button
                                    onClick={handleValidateToken}
                                    disabled={validating}
                                    className="btn btn-primary flex-1"
                                >
                                    {validating ? (
                                        <span className="spinner" />
                                    ) : (
                                        '✓ VALIDATE'
                                    )}
                                </button>
                                <button
                                    onClick={handleTamperToken}
                                    className="btn btn-danger flex-1"
                                    disabled={tokenData.isValid === false}
                                >
                                    ⚠️ TAMPER
                                </button>
                            </div>

                            {/* Info Box */}
                            <div className="p-3 bg-blue-500/10 rounded-lg border border-blue-500/20 mb-4">
                                <p className="text-xs text-blue-400">
                                    <strong>How it works:</strong> Each question paper is encrypted with AES-256
                                    and signed with RSA-PSS. Click &quot;Validate&quot; to verify the signature.
                                    Click &quot;Tamper&quot; to modify the token and see how tampering is detected.
                                </p>
                            </div>

                            <button
                                onClick={() => setTokenData(null)}
                                className="btn btn-secondary w-full"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                )}

                {/* Decrypted Content Modal */}
                {decryptedContent && (
                    <div className="modal-overlay" onClick={() => setDecryptedContent(null)}>
                        <div className="modal" onClick={(e) => e.stopPropagation()}>
                            <div className="text-center mb-4">
                                <span className="text-4xl">🔓</span>
                            </div>
                            <h3 className="modal-title text-center">Decrypted Content</h3>
                            <p className="text-sm text-gray-500 text-center mb-4">
                                Integrity verified ✓
                            </p>
                            <div className="p-4 bg-gray-900 rounded-lg border border-gray-700 mb-4">
                                <p className="text-lg font-mono text-center text-green-400">
                                    {decryptedContent.content}
                                </p>
                            </div>
                            <button
                                onClick={() => {
                                    navigator.clipboard.writeText(decryptedContent.content);
                                }}
                                className="btn btn-secondary w-full mb-2"
                            >
                                📋 Copy to Clipboard
                            </button>
                            <button
                                onClick={() => setDecryptedContent(null)}
                                className="btn btn-primary w-full"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
}
