export type CalculatedScore = {
  grade: string;
  totalScore: number;
};

function scoreInHundredths(value: string): number | null {
  const normalized = value.trim();
  if (!/^(?:\d{1,2}(?:\.\d{1,2})?|\.\d{1,2})$/.test(normalized)) return null;
  const numericValue = Number(normalized);
  if (!Number.isFinite(numericValue) || numericValue < 0 || numericValue > 10) return null;
  return Math.round(numericValue * 100);
}

export function isValidScoreInput(value: string): boolean {
  return scoreInHundredths(value) !== null;
}

export function calculateScoreResult(
  attendance: string,
  midterm: string,
  finalScore: string,
): CalculatedScore | null {
  const attendanceValue = scoreInHundredths(attendance);
  const midtermValue = scoreInHundredths(midterm);
  const finalValue = scoreInHundredths(finalScore);
  if (attendanceValue === null || midtermValue === null || finalValue === null) return null;

  // Inputs have at most two decimals. Integer arithmetic mirrors BigDecimal HALF_UP on the backend.
  const weightedNumerator = midtermValue * 21 + attendanceValue * 9 + finalValue * 70;
  const totalScore = Math.floor((weightedNumerator + 500) / 1000) / 10;
  const grade = totalScore >= 9 ? 'A+'
    : totalScore >= 8.5 ? 'A'
      : totalScore >= 7.8 ? 'B+'
        : totalScore >= 7 ? 'B'
          : totalScore >= 6.3 ? 'C+'
            : totalScore >= 5.5 ? 'C'
              : totalScore >= 4.8 ? 'D+'
                : totalScore >= 4 ? 'D' : 'F';

  return { grade, totalScore };
}

export function scoreGradeTone(grade: string | null): string {
  const first = grade?.trim().toUpperCase().charAt(0);
  if (first === 'A') return 'grade-excellent';
  if (first === 'B') return 'grade-good';
  if (first === 'C') return 'grade-average';
  if (first === 'D') return 'grade-warning';
  if (first === 'F') return 'grade-failed';
  return 'grade-pending';
}

export function formatScore(value: number | null): string {
  return value === null
    ? '—'
    : new Intl.NumberFormat('vi-VN', { maximumFractionDigits: 2 }).format(value);
}
