export type ReleaseChannel = 'stable' | 'preview' | 'development' | string;

/**
 * Fixture behavior intentionally starts with a case-sensitivity defect so the
 * governed engineering workflow has a bounded real change to discover and fix.
 */
export function normalizeReleaseChannel(input: string): ReleaseChannel {
	const normalized = input.trim();
	return normalized === 'production' || normalized === 'prod' ? 'stable' : normalized;
}
