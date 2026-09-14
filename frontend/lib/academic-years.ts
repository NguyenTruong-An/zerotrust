const ACADEMIC_YEAR_START_MONTH = 7;
const PAST_YEAR_COUNT = 11;

export function currentAcademicYear(today = new Date()): string {
  const startYear = today.getMonth() >= ACADEMIC_YEAR_START_MONTH
    ? today.getFullYear()
    : today.getFullYear() - 1;
  return `${startYear}-${startYear + 1}`;
}

export function academicYearOptions(selectedYear?: string | null): string[] {
  const currentStartYear = Number(currentAcademicYear().slice(0, 4));
  const years = Array.from(
    { length: PAST_YEAR_COUNT + 2 },
    (_, index) => {
      const startYear = currentStartYear + 1 - index;
      return `${startYear}-${startYear + 1}`;
    },
  );

  if (selectedYear && !years.includes(selectedYear)) {
    years.push(selectedYear);
  }

  return years.sort((left, right) => right.localeCompare(left));
}
