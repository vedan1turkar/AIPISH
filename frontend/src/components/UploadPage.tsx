import { useEffect, useRef, useState } from 'react'
import {
  uploadEml, uploadEmlWithAssessment, getAnalysis, listAnalyses, runThreatIntel, ApiError,
  type AnalysisDetail, type AnalysisSummary,
} from '../api/client'
import {
  Button, DataTable, EmptyLine, ErrorAlert, LED, Panel, SkeletonRows, StatusTag, formatBytes, formatDate, verdictTone,
} from './ui'

const MAX_MB = 10

function validateFile(file: File): string | null {
  const isEml =
    file.name.toLowerCase().endsWith('.eml') ||
    file.type === 'message/rfc822' ||
    file.type === 'application/octet-stream'
  if (!isEml) return 'Only .eml email files can be analysed. Please choose a file saved as .eml.'
  if (file.size === 0) return 'That file is empty — nothing to analyse.'
  if (file.size > MAX_MB * 1024 * 1024) return `That file is larger than the ${MAX_MB} MB limit.`
  return null
}

export default function UploadPage({
  onAnalyzed,
}: {
  onAnalyzed: (analysis: AnalysisDetail) => void
}) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [validationMsg, setValidationMsg] = useState<string | null>(null)
  const [status, setStatus] = useState<'idle' | 'uploading' | 'analyzing'>('idle')
  const [error, setError] = useState<{ message: string; code?: string } | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  // Opt-in: ML + SHAP must read the original bytes, which the default hash_only
  // policy discards after this request, so they can only run at upload time.
  const [runAi, setRunAi] = useState(false)
  // P5a: external threat-intel lookups are off unless explicitly consented to here or in the Threat intel tab.
  const [runIntel, setRunIntel] = useState(false)
  const [intelNote, setIntelNote] = useState<string | null>(null)
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (status !== 'analyzing') return
    setElapsed(0)
    const t0 = Date.now()
    const timer = window.setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 1000)
    return () => window.clearInterval(timer)
  }, [status])

  function pickFile(file: File | null | undefined) {
    setError(null)
    if (!file) {
      setSelectedFile(null)
      setValidationMsg(null)
      return
    }
    const problem = validateFile(file)
    setValidationMsg(problem)
    setSelectedFile(problem ? null : file)
  }

  async function submit() {
    if (!selectedFile || status === 'uploading' || status === 'analyzing') return
    setStatus('uploading')
    setError(null)
    try {
      setStatus('analyzing')
      const detail = runAi
        ? await getAnalysis((await uploadEmlWithAssessment(selectedFile)).analysis_id)
        : await uploadEml(selectedFile)
      if (runIntel) {
        setIntelNote('Running consented threat-intel lookups…')
        try {
          await runThreatIntel(detail.id, { consent: true, source: 'upload' })
        } catch {
          /* the analysis is complete; the Threat intel tab shows the stored state and allows a retry */
        } finally {
          setIntelNote(null)
        }
      }
      onAnalyzed(detail)
      pickFile(null)
      if (inputRef.current) inputRef.current.value = ''
    } catch (err) {
      if (err instanceof ApiError && err.status === 0) {
        setError({ message: err.message, code: err.code })
      } else if (err instanceof ApiError) {
        setError({ message: friendlyUploadError(err), code: err.code })
      } else if (err instanceof DOMException && err.name === 'AbortError') {
        /* user cancelled — ignore */
      } else {
        setError({ message: err instanceof Error ? err.message : 'Unexpected error' })
      }
      setStatus('idle')
    }
  }

  const busy = status === 'uploading' || status === 'analyzing'
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-fg">Analyse an email</h1>
        <p className="text-sm text-muted">
          Upload a raw <code className="bg-surface-2 px-1 font-mono">.eml</code> file
          (saved from any mail client — “View original / Save as .eml”). The message is parsed
          on your configured backend. By default only its SHA-256 and size are kept, not the raw
          file. DNS/RDAP/IP-geo enrichment and consented threat-intel lookups send bare
          indicators (domains, IPs, hashes), never message content.
        </p>
      </div>
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="New analysis" className="xl:col-span-7"
               status={<span className="font-mono text-xs">max {MAX_MB} MB · .eml / message/rfc822</span>}>
          <label
            className="flex min-h-[132px] cursor-pointer flex-col items-center justify-center border border-dashed border-line-strong bg-bg px-4 py-6 text-center hover:border-accent hover:bg-surface-2"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault()
              pickFile(e.dataTransfer.files?.[0])
            }}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".eml,message/rfc822"
              className="sr-only"
              onChange={(e) => pickFile(e.target.files?.[0])}
              disabled={busy}
            />
            <span className="font-mono text-sm text-fg">
              {selectedFile ? selectedFile.name : 'Drop an .eml here or click to choose'}
            </span>
            <span className="mt-1 text-sm text-muted">
              {selectedFile
                ? `${formatBytes(selectedFile.size)} — ready to analyse`
                : `Maximum ${MAX_MB} MB · one file at a time`}
            </span>
          </label>

          {validationMsg && (
            <p className="mt-3 flex items-center gap-2 border border-warn-line bg-warn-weak px-3 py-1.5 text-sm text-warn" role="alert">
              <LED tone="warn" />{validationMsg}
            </p>
          )}
          {error && (
            <div className="mt-3">
              <ErrorAlert message={error.message} code={error.code} onDismiss={() => setError(null)} />
            </div>
          )}

          <fieldset className="mt-3 border-t border-line">
            <legend className="sr-only">Options</legend>
            <label className="flex items-start gap-3 border-b border-line py-2.5">
              <input type="checkbox" className="mt-1 accent-[var(--accent)]" checked={runAi}
                     onChange={(e) => setRunAi(e.target.checked)} disabled={busy} />
              <span className="min-w-0">
                <span className="block text-sm text-fg">
                  Run AI assessment: ML classification, SHAP explanation and a local Mistral forensic summary
                </span>
                <span className="block text-sm text-muted">
                  This adds about 1–2 minutes. It runs on this backend's local models, and no email data leaves
                  the server. ML and SHAP can only run now, while the original bytes are available.
                </span>
              </span>
            </label>
            <label className="flex items-start gap-3 border-b border-line py-2.5">
              <input type="checkbox" className="mt-1 accent-[var(--accent)]" checked={runIntel}
                     onChange={(e) => setRunIntel(e.target.checked)} disabled={busy} />
              <span className="min-w-0">
                <span className="block text-sm text-fg">
                  I consent to external threat-intel lookups for this analysis (VirusTotal, AbuseIPDB, Shodan, IPinfo, Tor exit list)
                </span>
                <span className="block text-sm text-muted">
                  Off by default. Only bare public indicators are sent: IPs, domains and attachment SHA-256 hashes. The
                  subject, body, addresses, headers, URL paths and attachments are never sent. Results are informational and
                  do not change the verdict.
                </span>
              </span>
            </label>
          </fieldset>

          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={submit} disabled={!selectedFile || busy}>
              {busy ? (intelNote ?? (status === 'uploading' ? 'Uploading…' : 'Analysing…')) : 'Analyse email'}
            </Button>
            {busy && (
              <span className="flex items-center gap-2 text-sm text-muted" role="status">
                <LED tone="accent" className="animate-pulse" />
                {status === 'uploading'
                  ? 'Uploading the .eml to the backend…'
                  : runAi
                    ? `Running forensics, scoring, ML and SHAP, then the local language model. This usually takes about 1–2 minutes (${elapsed}s elapsed; no stage-by-stage progress is reported).`
                    : 'Running header forensics, authentication checks and scoring…'}
              </span>
            )}
          </div>
          <p className="mt-3 text-sm text-muted">
            .eml files carry the full original message: headers, body and attachments metadata.
          </p>
        </Panel>

        <RecentUploads className="xl:col-span-5" />
      </div>
    </div>
  )
}

function RecentUploads({ className = '' }: { className?: string }) {
  const [rows, setRows] = useState<AnalysisSummary[] | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    const ctl = new AbortController()
    listAnalyses(ctl.signal).then(setRows).catch(() => { if (!ctl.signal.aborted) setFailed(true) })
    return () => ctl.abort()
  }, [])
  return (
    <Panel title="Recent analyses" className={className} bodyClassName="p-0"
           status={<a href="#history" className="font-mono text-xs uppercase text-accent hover:underline">view all</a>}>
      {failed ? <div className="p-3"><EmptyLine>Recent analyses could not be loaded.</EmptyLine></div>
        : !rows ? <div className="p-3"><SkeletonRows rows={5} label="Loading recent analyses…" /></div>
        : (
          <DataTable<AnalysisSummary>
            label="Recent analyses"
            rows={rows.slice(0, 10)}
            rowKey={(r) => r.id}
            empty="No analyses yet — the first upload will appear here."
            columns={[
              { key: 'v', header: 'Verdict', render: (r) => <StatusTag tone={verdictTone(r.detection_verdict)}>{(r.detection_verdict ?? 'unknown').replace(/_/g, ' ')}</StatusTag> },
              { key: 's', header: 'Score', align: 'right', mono: true, render: (r) => r.detection_score },
              { key: 'subj', header: 'Subject', className: 'max-w-0 w-full', render: (r) => (
                <a href={`#analysis/${r.id}`} className="block truncate text-accent hover:underline">{r.subject || '(no subject)'}</a>) },
              { key: 't', header: 'Received', mono: true, className: 'whitespace-nowrap text-muted', render: (r) => formatDate(r.created_at) },
            ]}
          />
        )}
    </Panel>
  )
}

function friendlyUploadError(err: ApiError): string {
  switch (err.code) {
    case 'PAYLOAD_TOO_LARGE':
      return 'That file exceeds the server upload limit. Try a smaller .eml.'
    case 'EMPTY_FILE':
      return 'The server received an empty file — the .eml may have failed to attach.'
    case 'UNSUPPORTED_MEDIA_TYPE':
      return 'Only .eml (message/rfc822) files are accepted.'
    case 'NETWORK_ERROR':
      return 'Cannot reach the analysis backend. Check that it is running on port 8000.'
    default:
      return err.message
  }
}
