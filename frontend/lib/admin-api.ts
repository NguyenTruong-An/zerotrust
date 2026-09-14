import { apiFetch, AuthenticationExpiredError } from './api';

export type ApiResponse<T> = {
  data: T;
  message: string;
  success: boolean;
};

export type PageResponse<T> = {
  content: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  first: boolean;
  last: boolean;
};

export type StudentClass = {
  id: string;
  classCode: string;
  className: string;
  department: string;
  courseYears: string;
};

export type Subject = {
  id: string;
  subjectCode: string;
  subjectName: string;
  credits: number;
  description: string | null;
};

export type Student = {
  id: string;
  userId: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  status: 'ACTIVE' | 'INACTIVE' | 'DELETED';
  studentCode: string;
  dateOfBirth: string;
  gender: 'MALE' | 'FEMALE' | 'OTHER';
  phone: string | null;
  address: string | null;
  classCode: string;
  className: string;
};

export type Score = {
  id: string;
  studentId: string;
  studentCode: string;
  subjectId: string;
  subjectCode: string;
  subjectName: string;
  semester: number;
  academicYear: string;
  attendanceScore: number | null;
  midtermScore: number | null;
  finalScore: number | null;
  totalScore: number | null;
  grade: string | null;
};

export type SubjectScoreSheetRow = {
  scoreId: string | null;
  studentId: string;
  studentCode: string;
  firstName: string;
  lastName: string;
  classCode: string;
  className: string;
  semester: number | null;
  academicYear: string | null;
  attendanceScore: number | null;
  midtermScore: number | null;
  finalScore: number | null;
  totalScore: number | null;
  grade: string | null;
};

export type BatchScoreResult = {
  created: number;
  updated: number;
  scores: Score[];
};

export type UserAccount = {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  status: 'ACTIVE' | 'INACTIVE' | 'DELETED';
};

type ApiErrorBody = {
  message?: unknown;
  error?: unknown;
};

export class AdminApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'AdminApiError';
    this.status = status;
  }
}

export function emptyPage<T>(size = 10): PageResponse<T> {
  return {
    content: [],
    page: 0,
    size,
    totalElements: 0,
    totalPages: 0,
    first: true,
    last: true,
  };
}

function errorMessage(body: ApiErrorBody | null, fallback: string): string {
  if (typeof body?.message === 'string' && body.message.trim()) {
    return body.message;
  }

  if (body?.message && typeof body.message === 'object') {
    const messages = Object.values(body.message as Record<string, unknown>)
      .filter((value): value is string => typeof value === 'string' && value.trim().length > 0);
    if (messages.length) return messages.join('. ');
  }

  if (typeof body?.error === 'string' && body.error.trim()) return body.error;
  return fallback;
}

export async function portalRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await apiFetch(path, { ...init, headers });
  if (response.status === 401) throw new AuthenticationExpiredError();

  const payload = (await response.json().catch(() => null)) as
    | ApiResponse<T>
    | ApiErrorBody
    | null;

  if (!response.ok) {
    throw new AdminApiError(
      errorMessage(payload as ApiErrorBody | null, `Yêu cầu thất bại (${response.status}).`),
      response.status,
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  if (!payload || !('data' in payload)) {
    throw new AdminApiError('Phản hồi từ máy chủ không hợp lệ.', response.status);
  }

  return payload.data;
}

export async function adminRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  return portalRequest<T>(path, init);
}

export function queryPath(path: string, values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && String(value).trim() !== '') {
      params.set(key, String(value).trim());
    }
  });
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}
