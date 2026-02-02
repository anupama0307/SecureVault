import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureVault - Academic Password Manager",
  description: "A secure password and document management system for academic institutions",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
