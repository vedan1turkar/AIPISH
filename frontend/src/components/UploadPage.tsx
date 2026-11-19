import { useRef, useState } from 'react'
import { uploadEml, uploadEmlWithAssessment, getAnalysis, ApiError, type AnalysisDetail } from '../api/client'
import { ErrorAlert, Spinner } from './ui'

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

  return (
    <div className="mx-auto max-w-2xl">
      <div className="rounded-xl border border-gray-200 bg-white shadow-sm">
        <div className="border-b border-gray-100 px-6 py-5">
          <h2 className="text-base font-semibold text-gray-900">Analyse an email</h2>
          <p className="mt-1 text-sm text-gray-500">
            Upload a raw <code className="rounded bg-gray-100 px-1">.eml</code> file
            (saved from any mail client — “View original / Save as .eml”). Analysis runs
            entirely on your configured backend; the message body is parsed server-side and
            the raw file is retained there.
          </p>
        </div>

        <div className="px-6 py-5">
          <label
            className="block cursor-pointer rounded-lg border-2 border-dashed border-gray-300 bg-gray-50 px-6 py-10 text-center transition-colors hover:border-indigo-400 hover:bg-indigo-50/40"
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
              disabled={status === 'uploading' || status === 'analyzing'}
            />
            <span className="text-3xl" aria-hidden>
              ✉️
            </span>
            <p className="mt-2 text-sm font-medium text-gray-700">
              {selectedFile ? selectedFile.name : 'Drop an .eml here or click to choose'}
            </p>
            <p className="mt-1 text-xs text-gray-400">
              {selectedFile
                ? `${formatBytes(selectedFile.size)} — ready to analyse`
                : `Maximum ${MAX_MB} MB · one file at a time`}
            </p>
          </label>

          {validationMsg && (
            <p className="mt-3 rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-800" role="alert">
              {validationMsg}
            </p>
          )}

          {error && (
            <div className="mt-3">
              <ErrorAlert message={error.message} code={error.code} onDismiss={() => setError(null)} />
            </div>
          )}

          <label className="mt-4 flex items-start gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={runAi}
              onChange={(e) => setRunAi(e.target.checked)}
              disabled={status === 'uploading' || status === 'analyzing'}
            />
            <span>
              Run AI assessment: ML classification, SHAP explanation and a local Mistral forensic summary
              <span className="block text-xs text-gray-400">
                This adds about one minute. It runs on this backend's local models, and no email data leaves
                the server. ML and SHAP can only run now, while the original bytes are available.
              </span>
            </span>
          </label>

          <button
            onClick={submit}
            disabled={!selectedFile || status === 'uploading' || status === 'analyzing'}
            className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-gray-300"
          >
            {status === 'uploading' || status === 'analyzing' ? (
              <Spinner label={status === 'uploading' ? 'Uploading…' : 'Analysing…'} />
            ) : (
              'Analyse email'
            )}
          </button>

          {(status === 'uploading' || status === 'analyzing') && (
            <div className="mt-4">
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-100">
                <div
                  className={`h-full rounded-full bg-indigo-500 ${
                    status === 'uploading' ? 'w-1/3' : 'w-2/3'
                  } transition-all`}
                />
              </div>
              <p className="mt-2 text-center text-xs text-gray-400">
                {status === 'uploading'
                  ? 'Uploading the .eml to the backend…'
                  : runAi
                    ? 'Running forensics, scoring, ML and SHAP, then the local language model (about 1 minute)…'
                    : 'Running header forensics, authentication checks and scoring…'}
              </p>
            </div>
          )}
        </div>
      </div>

      <p className="mt-3 text-center text-xs text-gray-400">
        .eml files carry the full original message: headers, body and attachments metadata.
      </p>
    </div>
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

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
