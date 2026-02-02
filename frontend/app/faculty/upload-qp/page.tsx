'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { resourcesApi } from '@/lib/api';

export default function UploadQuestionPaperPage() {
    const router = useRouter();
    const [subject, setSubject] = useState('');
    const [title, setTitle] = useState('');
    const [file, setFile] = useState<File | null>(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!file) {
            setError('Please select a file');
            return;
        }

        setError('');
        setLoading(true);

        try {
            const response = await resourcesApi.uploadQuestionPaper(subject, title, file);
            if (response.success) {
                router.push('/faculty/my-uploads');
            } else {
                setError(response.error || 'Failed to upload');
            }
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
                        <Link href="/faculty/upload-qp" className="sidebar-link active">
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
                            <span className="text-2xl">📝</span>
                            Upload Question Paper
                        </h1>

                        <p className="text-gray-500 text-sm mb-6">
                            Upload exam question papers securely. The file will be encrypted and digitally
                            signed to ensure integrity and prevent tampering.
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
                                <label className="label">Exam Title</label>
                                <input
                                    type="text"
                                    className="input"
                                    placeholder="e.g., CAT 1 - January 2026"
                                    value={title}
                                    onChange={(e) => setTitle(e.target.value)}
                                    required
                                />
                            </div>

                            <div className="mb-6">
                                <label className="label">Question Paper File</label>
                                <div className="border-2 border-dashed border-gray-700 rounded-lg p-6 text-center hover:border-gray-600 transition-colors">
                                    <input
                                        type="file"
                                        accept=".pdf,.doc,.docx"
                                        onChange={(e) => setFile(e.target.files?.[0] || null)}
                                        className="hidden"
                                        id="file-upload"
                                    />
                                    <label htmlFor="file-upload" className="cursor-pointer">
                                        {file ? (
                                            <>
                                                <span className="text-3xl block mb-2">📝</span>
                                                <p className="text-white font-medium">{file.name}</p>
                                                <p className="text-sm text-gray-500 mt-1">
                                                    {(file.size / 1024 / 1024).toFixed(2)} MB
                                                </p>
                                            </>
                                        ) : (
                                            <>
                                                <span className="text-3xl block mb-2">📤</span>
                                                <p className="text-gray-400">Click to select a file</p>
                                                <p className="text-sm text-gray-600 mt-1">PDF, DOC, or DOCX</p>
                                            </>
                                        )}
                                    </label>
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
                                    disabled={loading || !file}
                                >
                                    {loading ? <span className="spinner" /> : 'Upload & Sign'}
                                </button>
                            </div>
                        </form>

                        <div className="mt-6 p-4 rounded-lg bg-green-500/10 border border-green-500/20">
                            <p className="text-sm text-green-400">
                                ✓ <strong>Digital Signature:</strong> Your question paper will be signed with
                                RSA-PSS. Any modification will invalidate the signature, ensuring tamper detection.
                            </p>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}
