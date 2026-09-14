'use client';

import { ReactNode, useEffect } from 'react';
import {
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Inbox,
  LoaderCircle,
  RefreshCw,
  X,
} from 'lucide-react';

export function Modal({
  eyebrow,
  title,
  description,
  children,
  onClose,
  wide = false,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', closeOnEscape);
    };
  }, [onClose]);

  return (
    <div className="admin-modal-layer" role="presentation">
      <button className="admin-modal-backdrop" aria-label="Đóng hộp thoại" onClick={onClose} type="button" />
      <section
        aria-labelledby="admin-modal-title"
        aria-modal="true"
        className={`admin-modal ${wide ? 'admin-modal-wide' : ''}`}
        role="dialog"
      >
        <header className="admin-modal-header">
          <div>
            <p className="eyebrow">{eyebrow}</p>
            <h2 id="admin-modal-title">{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button aria-label="Đóng" className="admin-icon-button" onClick={onClose} type="button">
            <X aria-hidden="true" size={19} />
          </button>
        </header>
        <div className="admin-modal-body">{children}</div>
      </section>
    </div>
  );
}

export function PanelError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="admin-panel-message admin-panel-error" role="alert">
      <AlertCircle aria-hidden="true" size={23} />
      <div>
        <strong>Chưa tải được dữ liệu</strong>
        <span>{message}</span>
      </div>
      <button onClick={onRetry} type="button">
        <RefreshCw aria-hidden="true" size={15} /> Thử lại
      </button>
    </div>
  );
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className="admin-empty-state">
      <Inbox aria-hidden="true" size={27} />
      <strong>{title}</strong>
      <span>{description}</span>
    </div>
  );
}

export function TableSkeleton({ columns, rows = 5 }: { columns: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, index) => (
        <tr className="admin-skeleton-row" key={index}>
          <td colSpan={columns}><span /></td>
        </tr>
      ))}
    </>
  );
}

export function Pagination({
  page,
  totalPages,
  totalElements,
  first,
  last,
  onPageChange,
}: {
  page: number;
  totalPages: number;
  totalElements: number;
  first: boolean;
  last: boolean;
  onPageChange: (page: number) => void;
}) {
  return (
    <div className="admin-pagination" aria-label="Phân trang">
      <p>
        {totalElements} bản ghi
        {totalPages > 0 && <> · Trang <strong>{page + 1}</strong>/{totalPages}</>}
      </p>
      <div>
        <button disabled={first || totalPages === 0} onClick={() => onPageChange(page - 1)} type="button">
          <ChevronLeft aria-hidden="true" size={16} /> Trước
        </button>
        <button disabled={last || totalPages === 0} onClick={() => onPageChange(page + 1)} type="button">
          Sau <ChevronRight aria-hidden="true" size={16} />
        </button>
      </div>
    </div>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const normalized = status.toUpperCase();
  const label = normalized === 'ACTIVE'
    ? 'Đang hoạt động'
    : normalized === 'INACTIVE'
      ? 'Ngừng hoạt động'
      : 'Đã xóa';
  return <span className={`admin-status status-${normalized.toLowerCase()}`}>{label}</span>;
}

export function FormAlert({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div className="admin-form-alert" role="alert">
      <AlertCircle aria-hidden="true" size={17} />
      <span>{message}</span>
    </div>
  );
}

export function SubmitButton({ busy, children }: { busy: boolean; children: ReactNode }) {
  return (
    <button className="admin-primary-button" disabled={busy} type="submit">
      {busy ? <LoaderCircle className="spin" aria-hidden="true" size={17} /> : children}
      {busy && 'Đang lưu…'}
    </button>
  );
}
