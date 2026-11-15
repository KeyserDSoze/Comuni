import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowRight, Building2, CheckCircle2, ClipboardList, Files, Globe2,
  Layers3, LogOut, Menu, Moon, Plus, ShieldCheck, Sun, X,
} from 'lucide-react';
import { Button } from './components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';
import { getContext, getRecords, registerRecord, type OrganizationContext, type ProtocolRecord } from './api';
import { cn } from './lib/utils';

type Page = 'dashboard' | 'protocol';

function Brand() {
  const { t } = useTranslation();
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-sky-700 to-teal-500 text-white shadow-md">
        <Building2 aria-hidden="true" className="h-6 w-6" />
      </div>
      <div>
        <div className="text-xl font-bold tracking-tight text-foreground">{t('appName')}</div>
        <div className="text-[11px] font-medium text-muted-foreground">{t('appTagline')}</div>
      </div>
    </div>
  );
}

export function App() {
  const { t, i18n } = useTranslation();
  const [tokenInput, setTokenInput] = useState('');
  const [token, setToken] = useState('');
  const [context, setContext] = useState<OrganizationContext | null>(null);
  const [page, setPage] = useState<Page>('dashboard');
  const [dark, setDark] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [error, setError] = useState('');
  const [records, setRecords] = useState<ProtocolRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [newRecordOpen, setNewRecordOpen] = useState(false);
  const [subject, setSubject] = useState('');
  const [notice, setNotice] = useState('');
  const canWrite = Boolean(context?.roles.some(role => role === 'Admin' || role === 'Officer'));
  const protocolEnabled = Boolean(context?.modules.includes('protocol'));

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);

  useEffect(() => {
    if (!token) return;
    let active = true;
    void getContext(token).then(result => {
      if (!active) return;
      setContext(result);
      setError('');
    }).catch(() => {
      if (!active) return;
      setContext(null);
      setError(t('invalidToken'));
    });
    return () => { active = false; };
  }, [token, t]);

  const loadRecords = useCallback(async () => {
    if (!token) return;
    setLoadingRecords(true);
    try {
      const result = await getRecords(token);
      setRecords(result);
      setError('');
    } catch {
      setError(t('serverError'));
    } finally {
      setLoadingRecords(false);
    }
  }, [token, t]);

  useEffect(() => {
    if (page === 'protocol' && protocolEnabled) void loadRecords();
  }, [page, protocolEnabled, loadRecords]);

  function enter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (tokenInput.trim()) {
      setError('');
      setToken(tokenInput.trim());
      setPage('dashboard');
    }
  }

  function logout() {
    setToken('');
    setTokenInput('');
    setContext(null);
    setRecords([]);
    setPage('dashboard');
    setError('');
  }

  function navigate(next: Page) {
    if (next === 'protocol' && !protocolEnabled) return;
    setPage(next);
    setMenuOpen(false);
    setNotice('');
    setNewRecordOpen(false);
  }

  async function createRecord(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token || !canWrite || !protocolEnabled || !subject.trim()) return;
    try {
      await registerRecord(token, subject.trim());
      setSubject('');
      setNewRecordOpen(false);
      setNotice(t('created'));
      await loadRecords();
    } catch {
      setError(t('serverError'));
    }
  }

  const controls = (
    <div className="flex items-center gap-2">
      <Button variant="ghost" size="sm" aria-label={t('lang')} onClick={() => void i18n.changeLanguage(i18n.language === 'it' ? 'en' : 'it')}>
        <Globe2 className="h-4 w-4" aria-hidden="true" /> {i18n.language === 'it' ? 'EN' : 'IT'}
      </Button>
      <Button variant="outline" size="icon" aria-label={t('theme')} onClick={() => setDark(value => !value)}>
        {dark ? <Sun className="h-4 w-4" aria-hidden="true" /> : <Moon className="h-4 w-4" aria-hidden="true" />}
      </Button>
    </div>
  );

  if (!context) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <header className="mx-auto flex max-w-6xl items-center justify-between px-5 py-6">
          <Brand />{controls}
        </header>
        <main className="mx-auto grid max-w-6xl items-center gap-12 px-5 pb-20 pt-12 md:grid-cols-[1fr_420px] md:pt-28">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-teal-400/30 bg-teal-500/10 px-3 py-1 text-sm font-medium text-teal-700 dark:text-teal-300">
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />{t('secure')}
            </div>
            <h1 className="max-w-lg text-4xl font-extrabold leading-tight tracking-tight sm:text-5xl">{t('welcome')}</h1>
            <p className="mt-5 max-w-lg text-lg leading-relaxed text-muted-foreground">{t('subtitle')}</p>
            <div className="mt-8 flex items-center gap-3 text-sm text-muted-foreground">
              <Layers3 aria-hidden="true" className="h-5 w-5 text-teal-600" />{t('integration')}
            </div>
          </div>
          <Card className="border-sky-200/60 shadow-xl dark:border-slate-700">
            <CardHeader>
              <CardTitle>{t('access')}</CardTitle>
              <p className="text-sm text-muted-foreground">{t('tokenHelp')}</p>
            </CardHeader>
            <CardContent>
              <form onSubmit={enter} className="space-y-4">
                <div>
                  <label htmlFor="jwt" className="mb-2 block text-sm font-medium">{t('tokenLabel')}</label>
                  <input id="jwt" type="password" autoComplete="off" spellCheck={false}
                    className="h-11 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500"
                    value={tokenInput} onChange={event => setTokenInput(event.target.value)}
                    placeholder={t('tokenPlaceholder')} required />
                </div>
                {error && <p role="alert" className="text-sm text-rose-600">{error}</p>}
                <Button className="w-full" type="submit">{t('useToken')} <ArrowRight aria-hidden="true" className="h-4 w-4" /></Button>
              </form>
              <p className="mt-5 border-t border-border pt-4 text-xs leading-relaxed text-muted-foreground">{t('demoNotice')}</p>
            </CardContent>
          </Card>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground md:flex">
      {menuOpen && <button aria-label={t('closeMenu')} className="fixed inset-0 z-20 bg-slate-950/40 md:hidden" onClick={() => setMenuOpen(false)} />}
      <aside className={cn('fixed inset-y-0 left-0 z-30 flex w-64 -translate-x-full flex-col border-r border-border bg-card px-4 py-6 transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0', menuOpen && 'translate-x-0')}>
        <Brand />
        <p className="mt-10 px-3 text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">{t('workspace')}</p>
        <nav aria-label="Navigazione principale" className="mt-3 flex flex-col gap-2">
          <Button variant={page === 'dashboard' ? 'default' : 'ghost'} className="justify-start" onClick={() => navigate('dashboard')}>
            <Layers3 className="h-4 w-4" aria-hidden="true" />{t('dashboard')}
          </Button>
          {protocolEnabled && (
            <Button variant={page === 'protocol' ? 'default' : 'ghost'} className="justify-start" onClick={() => navigate('protocol')}>
              <Files className="h-4 w-4" aria-hidden="true" />{t('protocol')}
            </Button>
          )}
        </nav>
        <div className="mt-auto rounded-lg bg-muted p-4">
          <div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-teal-500" aria-hidden="true" />{t('secure')}</div>
          <p className="mt-1 text-xs text-muted-foreground">{t('onlyEnabled')}</p>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-10 flex min-h-20 items-center justify-between gap-3 border-b border-border bg-card/95 px-4 backdrop-blur sm:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <Button variant="ghost" size="icon" className="md:hidden" aria-label={t('menu')} onClick={() => setMenuOpen(true)}><Menu className="h-5 w-5" /></Button>
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-foreground sm:text-lg">{context.organizationName}</div>
              <div className="text-xs text-muted-foreground">{t('currentOrg')}</div>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">{controls}
            <Button variant="ghost" size="sm" onClick={logout}><LogOut className="h-4 w-4" aria-hidden="true" /><span className="hidden sm:inline">{t('signOut')}</span></Button>
          </div>
        </header>

        <main className="mx-auto max-w-7xl space-y-7 px-4 py-8 sm:px-8">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-sm font-semibold text-teal-600 dark:text-teal-400">{t('overview')} / {page === 'dashboard' ? t('dashboard') : t('protocol')}</p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight">{page === 'dashboard' ? t('welcome') : t('protocol')}</h1>
              <p className="mt-2 text-sm text-muted-foreground">{page === 'dashboard' ? t('subtitle') : t('protocolDesc')}</p>
            </div>
            {page === 'protocol' && canWrite && protocolEnabled && (
              <Button onClick={() => setNewRecordOpen(true)}><Plus className="h-4 w-4" aria-hidden="true" />{t('register')}</Button>
            )}
          </div>

          {error && <div role="alert" className="rounded-md border border-rose-300 bg-rose-50 p-3 text-sm text-rose-700 dark:bg-rose-950">{error}</div>}
          {notice && <div role="status" className="flex items-center gap-2 rounded-md border border-teal-300/60 bg-teal-500/10 p-3 text-sm"><CheckCircle2 className="h-4 w-4 text-teal-500" />{notice}</div>}

          {page === 'dashboard' ? (
            <>
              <div className="grid gap-4 sm:grid-cols-3">
                <Card><CardContent className="pt-5"><p className="text-sm text-muted-foreground">{t('currentOrg')}</p><p className="mt-3 truncate text-xl font-bold">{context.organizationName}</p><Building2 className="mt-4 h-6 w-6 text-teal-500" aria-hidden="true" /></CardContent></Card>
                <Card><CardContent className="pt-5"><p className="text-sm text-muted-foreground">{t('modules')}</p><p className="mt-3 text-3xl font-bold">{context.modules.length}</p><Layers3 className="mt-4 h-6 w-6 text-sky-500" aria-hidden="true" /></CardContent></Card>
                <Card><CardContent className="pt-5"><p className="text-sm text-muted-foreground">{t('role')}</p><p className="mt-3 truncate text-xl font-bold">{context.roles.join(', ')}</p><ShieldCheck className="mt-4 h-6 w-6 text-teal-500" aria-hidden="true" /></CardContent></Card>
              </div>
              <section>
                <h2 className="mb-4 text-xl font-semibold">{t('services')}</h2>
                {protocolEnabled ? (
                  <Card className="max-w-xl">
                    <CardHeader><div className="mb-2 flex h-11 w-11 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600"><ClipboardList className="h-6 w-6" /></div><CardTitle>{t('protocol')}</CardTitle></CardHeader>
                    <CardContent><p className="mb-5 text-sm text-muted-foreground">{t('protocolDesc')}</p>
                      <Button onClick={() => navigate('protocol')}>{t('openModule')} <ArrowRight className="h-4 w-4" aria-hidden="true" /></Button>
                    </CardContent>
                  </Card>
                ) : <Card><CardContent className="pt-5 text-muted-foreground">{t('noModules')}</CardContent></Card>}
              </section>
            </>
          ) : (
            <>
              {newRecordOpen && canWrite && (
                <Card className="max-w-2xl">
                  <CardHeader><CardTitle>{t('register')}</CardTitle></CardHeader>
                  <CardContent>
                    <form onSubmit={event => void createRecord(event)} className="space-y-4">
                      <div><label htmlFor="subject" className="mb-2 block text-sm font-medium">{t('subject')}</label>
                        <input id="subject" required maxLength={250} value={subject} onChange={event => setSubject(event.target.value)}
                          placeholder={t('subjectPlaceholder')} className="h-11 w-full rounded-md border border-border bg-background px-3 focus:outline-none focus:ring-2 focus:ring-teal-500" /></div>
                      <div className="flex gap-2"><Button type="submit">{t('save')}</Button><Button variant="outline" type="button" onClick={() => setNewRecordOpen(false)}><X className="h-4 w-4" />{t('cancel')}</Button></div>
                    </form>
                  </CardContent>
                </Card>
              )}
              <Card><CardHeader><CardTitle>{t('records')}</CardTitle></CardHeader>
                <CardContent>
                  {loadingRecords ? <p className="text-sm text-muted-foreground">{t('loading')}</p> : records.length === 0 ?
                    <p className="py-8 text-center text-sm text-muted-foreground">{t('noRecords')}</p> :
                    <ul className="divide-y divide-border">
                      {records.map(record => <li key={record.id} className="flex flex-wrap items-start justify-between gap-2 py-4">
                        <span className="font-medium">{record.subject}</span>
                        <time dateTime={record.registeredAt} className="text-xs text-muted-foreground">{new Date(record.registeredAt).toLocaleString(i18n.language)}</time>
                      </li>)}
                    </ul>}
                </CardContent>
              </Card>
              <p className="text-xs text-muted-foreground">{t('demoNotice')}</p>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
