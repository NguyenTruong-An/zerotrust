import type { Metadata } from 'next';
import '@fontsource/be-vietnam-pro/400.css';
import '@fontsource/be-vietnam-pro/500.css';
import '@fontsource/be-vietnam-pro/600.css';
import '@fontsource/be-vietnam-pro/700.css';
import '@fontsource/be-vietnam-pro/800.css';
import './globals.css';

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? 'http://localhost:3000';

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: 'Cổng học vụ | ZeroTrust Academic Portal',
  description: 'Quản trị dữ liệu và theo dõi kết quả học tập an toàn qua ZeroTrust Academic Portal.',
  openGraph: {
    title: 'ZeroTrust Academic Portal',
    description: 'Quản trị và tra cứu kết quả học tập an toàn',
    images: [{ url: '/og.png', width: 1200, height: 630 }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ZeroTrust Academic Portal',
    description: 'Quản trị và tra cứu kết quả học tập an toàn',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="vi">
      <body>{children}</body>
    </html>
  );
}
