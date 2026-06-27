import type { Metadata } from "next";
import { Inter, Space_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const spaceMono = Space_Mono({
  subsets: ["latin"],
  weight: ["400", "700"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "PromptSentry — Monitor",
  description: "Real-time prompt injection threat monitor",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${spaceMono.variable} h-full`}>
      <body className="min-h-full">
        {/* CRT vignette */}
        <div className="crt-vignette" />
        {/* Corner accents */}
        <div className="corner-accent tl" />
        <div className="corner-accent tr" />
        <div className="corner-accent bl" />
        <div className="corner-accent br" />
        <div style={{ position: "relative", zIndex: 1 }}>
          {children}
        </div>
      </body>
    </html>
  );
}
