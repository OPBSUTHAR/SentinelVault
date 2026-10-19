import { useEffect, useState } from 'react'
import { Dices, RefreshCw, ShieldCheck, Wand2 } from 'lucide-react'
import { ToolsApi, errText } from '../api'
import { Badge, Card, CopyButton, ScoreRing, StrengthMeter, useToast } from '../components/ui'

export default function GeneratorPage() {
  const [kind, setKind] = useState<'password' | 'passphrase'>('password')
  const [policy, setPolicy] = useState('strong')
  const [custom, setCustom] = useState(false)
  const [length, setLength] = useState(16)
  const [words, setWords] = useState(4)
  const [opts, setOpts] = useState({ upper: true, lower: true, digits: true, symbols: true, avoid_ambiguous: false })
  const [result, setResult] = useState('')
  const [report, setReport] = useState<any>(null)

  const [testPw, setTestPw] = useState('')
  const [testReport, setTestReport] = useState<any>(null)
  const toast = useToast()

  const generate = async () => {
    try {
      let d
      if (kind === 'passphrase') {
        d = await ToolsApi.generate({ kind: 'passphrase', words })
      } else if (custom) {
        d = await ToolsApi.generate({ length, ...opts })
      } else {
        d = await ToolsApi.generate({ policy })
      }
      setResult(d.password)
      const rep = await ToolsApi.strength(d.password)
      setReport(rep.report)
    } catch (e) {
      toast(errText(e), 'error')
    }
  }

  useEffect(() => {
    generate()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, policy, custom, length, words, opts])

  // live analysis of typed passwords
  useEffect(() => {
    if (!testPw) {
      setTestReport(null)
      return
    }
    const t = setTimeout(() => {
      ToolsApi.strength(testPw).then((d) => setTestReport(d.report)).catch(() => {})
    }, 220)
    return () => clearTimeout(t)
  }, [testPw])

  const tone = (s: number) => (s >= 80 ? 'ok' : s >= 60 ? 'info' : s >= 40 ? 'warn' : 'danger')

  return (
    <div className="grid cols-2" style={{ alignItems: 'start' }}>
      <Card title="Password generator" sub="Cryptographically secure (CSPRNG) — generated locally on the server, never stored">
        <div className="tab-row" style={{ marginBottom: 14 }}>
          <button className={`tab ${kind === 'password' ? 'active' : ''}`} onClick={() => setKind('password')}>Password</button>
          <button className={`tab ${kind === 'passphrase' ? 'active' : ''}`} onClick={() => setKind('passphrase')}>Passphrase</button>
        </div>

        {kind === 'password' ? (
          <>
            <div className="field">
              <label>Policy</label>
              <select className="input" value={custom ? 'custom' : policy} onChange={(e) => {
                if (e.target.value === 'custom') setCustom(true)
                else { setCustom(false); setPolicy(e.target.value) }
              }}>
                <option value="basic">Basic — 12 chars, letters+digits</option>
                <option value="strong">Strong — 16 chars, all classes</option>
                <option value="paranoid">Paranoid — 24 chars, all classes</option>
                <option value="pin">PIN — 6 digits</option>
                <option value="custom">Custom…</option>
              </select>
            </div>
            {custom && (
              <>
                <div className="field">
                  <label>Length: {length}</label>
                  <input type="range" min={8} max={64} value={length} onChange={(e) => setLength(+e.target.value)} style={{ width: '100%' }} />
                </div>
                <div className="row wrap" style={{ gap: 14, marginBottom: 12 }}>
                  {([['upper', 'A-Z'], ['lower', 'a-z'], ['digits', '0-9'], ['symbols', '!@#'], ['avoid_ambiguous', 'no look-alikes']] as const).map(([key, label]) => (
                    <label key={key} className="row small" style={{ gap: 6, cursor: 'pointer' }}>
                      <input type="checkbox" checked={(opts as any)[key]} onChange={(e) => setOpts({ ...opts, [key]: e.target.checked })} /> {label}
                    </label>
                  ))}
                </div>
              </>
            )}
          </>
        ) : (
          <div className="field">
            <label>Words: {words}</label>
            <input type="range" min={3} max={8} value={words} onChange={(e) => setWords(+e.target.value)} style={{ width: '100%' }} />
          </div>
        )}

        <button className="btn wide" onClick={generate}><Dices size={15} /> Generate new</button>

        {result && (
          <div style={{ marginTop: 16 }}>
            <div className="row">
              <code className="mono" style={{ flex: 1, background: 'rgba(7,11,22,.85)', padding: '12px 14px', borderRadius: 10, fontSize: 15, wordBreak: 'break-all' }}>{result}</code>
              <CopyButton text={result} />
            </div>
            {report && (
              <div style={{ marginTop: 12 }}>
                <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
                  <span className="muted small">Strength</span>
                  <Badge tone={tone(report.score)}>{report.score}/100 · {report.rating}</Badge>
                </div>
                <StrengthMeter score={report.score} />
              </div>
            )}
          </div>
        )}
      </Card>

      <div className="grid" style={{ gap: 16 }}>
        <Card title="Password strength analyzer" sub="Type any password — scored with a zxcvbn-style model (patterns, dictionaries, sequences)">
          <div className="field">
            <input className="input mono" value={testPw} onChange={(e) => setTestPw(e.target.value)} placeholder="Type a password to analyze…" />
          </div>
          {testReport ? (
            <>
              <div className="row" style={{ gap: 18, alignItems: 'center', marginBottom: 12 }}>
                <ScoreRing score={testReport.score} grade={testReport.rating?.slice(0, 1).toUpperCase()} />
                <div>
                  <Badge tone={tone(testReport.score)}>{testReport.rating}</Badge>
                  <div className="muted small" style={{ marginTop: 6 }}>
                    ~{Math.round(testReport.entropy_bits)} bits of entropy · {testReport.length} chars · {testReport.charset_classes} character classes
                  </div>
                  <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
                    {(testReport.patterns || []).length === 0
                      ? <span className="muted small">No weak patterns detected</span>
                      : (testReport.patterns || []).map((p: any, i: number) => <Badge key={i} tone="warn">{typeof p === 'string' ? p : p.type || p.name}</Badge>)}
                  </div>
                </div>
              </div>
              {(testReport.feedback || []).length > 0 && (
                <ul className="small muted" style={{ margin: '0 0 12px 18px' }}>
                  {(testReport.feedback || []).map((f: string, i: number) => <li key={i}>{f}</li>)}
                </ul>
              )}
              <div className="grid cols-2" style={{ gap: 10 }}>
                {Object.entries(testReport.crack_times || {}).map(([k, v]) => (
                  <div key={k} className="kv">
                    <span className="muted small">{k.replace(/_/g, ' ')}</span>
                    <b className="small">{String(v)}</b>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="muted small"><ShieldCheck size={14} /> Results appear as you type. Nothing is stored.</div>
          )}
        </Card>

        <Card title="Why this matters">
          <ul className="small muted" style={{ margin: '0 0 0 18px', lineHeight: 1.8 }}>
            <li><Wand2 size={12} /> Every generated password is checked against breach corpora before you save it.</li>
            <li><RefreshCw size={12} /> Weak or reused passwords can be auto-rotated from the vault or dashboard.</li>
            <li><ShieldCheck size={12} /> Strength scoring runs offline — passwords never leave your machine.</li>
          </ul>
        </Card>
      </div>
    </div>
  )
}
