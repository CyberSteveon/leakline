// Completion events can precede start_scan's response. The stored result keyed by
// the returned scan ID is authoritative; progress events are advisory only.
export async function waitForResult(scanId, fetchResult, wait, isCurrent) {
  while (isCurrent()) {
    try {
      const result = await fetchResult(scanId)
      if (result?.scanId !== scanId) throw new Error('Unexpected scan result.')
      return result
    } catch (error) {
      if (error?.code !== 'scan_running') throw error
      await wait()
    }
  }
  return null
}

export function describeOutcome(result) {
  switch (result.status) {
    case 'cancelled': return 'Scan cancelled. Results cover only work completed before cancellation.'
    case 'partial': return 'Partial scan. Some checks or files were not completed.'
    case 'failed': return 'Scan failed. No reliable conclusion is available.'
    case 'completed_with_issues': return 'Scan finished with issues. Review the coverage before interpreting the findings.'
    case 'completed':
      if (result.issues.length || !result.scannerRuns.length ||
          result.scannerRuns.some(run => run.status !== 'completed')) {
        return 'Scan coverage is incomplete. Review the scanner outcomes.'
      }
      if (result.findings.length) return 'Scan completed with findings.'
      if (!result.coverage.nativeProcessedFiles) return 'No eligible files were checked by native rules.'
      return 'No findings from the checks that ran.'
    default: return 'Scan outcome unknown. No conclusion is available.'
  }
}
