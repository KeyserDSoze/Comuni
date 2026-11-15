import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowRight, Building2, CheckCircle2, ClipboardList, Files, Globe2,
  Layers3, LogOut, Menu, Moon, Plus, Settings2, ShieldCheck, Sun, X, LockKeyhole,
} from 'lucide-react';
import { Button } from './components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';
import { getContext, getRecords, getAdminModules, setAdminModule, getAdminMemberships, setAdminMembership, registerRecord, getPlatformSession, type PlatformSession, type OrganizationContext, type ProtocolRecord, type AdminModule, type AdminMembership } from './api';
import { cn } from './lib/utils';
import {
  beginOidcLogin, captureOidcCallback, clearPendingOidc,
  completeOidcLogin, loadBrowserOidc,
  type BrowserOidcConfig, type OidcAccessToken
} from './oidc';

type Page = 'dashboard' | 'protocol' | 'admin' | 'platform';

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
  const [browserOidc, setBrowserOidc] = useState<BrowserOidcConfig | null>(null);
  const [oidcExpiresAt, setOidcExpiresAt] = useState<number | null>(null);
  const authBootstrap = useRef<Promise<{ config: BrowserOidcConfig; result: OidcAccessToken | null }> | null>(null);
  const [context, setContext] = useState<OrganizationContext | null>(null);
  const [platformSession, setPlatformSession] = useState<PlatformSession | null>(null);
  const [checkingSession, setCheckingSession] = useState(false);
  const [page, setPage] = useState<Page>('dashboard');
  const [dark, setDark] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [error, setError] = useState('');
  const [records, setRecords] = useState<ProtocolRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [newRecordOpen, setNewRecordOpen] = useState(false);
  const [subject, setSubject] = useState('');
  const [notice, setNotice] = useState('');
  const [adminModules, setAdminModules] = useState<AdminModule[]>([]);
  const [loadingAdmin, setLoadingAdmin] = useState(false);
  const [savingAdmin, setSavingAdmin] = useState(false);
  const [adminMemberships, setAdminMemberships] = useState<AdminMembership[]>([]);
  const [memberSubject, setMemberSubject] = useState('');
  const [memberRole, setMemberRole] = useState<'Reader' | 'Officer'>('Reader');
  const [savingMembership, setSavingMembership] = useState(false);
  const canWrite = Boolean(context?.roles.some(role => role === 'Admin' || role === 'Officer'));
  const canAdmin = Boolean(context?.roles.includes('Admin'));
  const protocolEnabled = Boolean(context?.modules.includes('protocol'));

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);

  useEffect(() => {
    let active = true;
    // React StrictMode invokes effects twice in Development. Keep the same
    // single-use callback/PKCE exchange promise across both invocations.
    if (!authBootstrap.current) {
      const callback = captureOidcCallback();
      authBootstrap.current = loadBrowserOidc().then(async config => ({
        config, result: await completeOidcLogin(config, callback)
      }));
    }
    void authBootstrap.current.then(({ config, result }) => {
      if (!active) return;
      setBrowserOidc(config);
      if (result) {
        setToken(result.accessToken);
        setOidcExpiresAt(result.expiresAt);
        setPage('dashboard');
      }
    }).catch(() => {
      if (!active) return;
      // Never reopen the technical JWT form on a failed OIDC callback.
      setBrowserOidc({ mode: 'Oidc', enabled: false, issuer: null,
        clientId: null, authorizationEndpoint: null, tokenEndpoint: null, scope: null });
      setError(t('oidcError'));
    });
    return () => { active = false; };
  }, [t]);

  useEffect(() => {
    if (!oidcExpiresAt) return;
    const remaining = oidcExpiresAt - Date.now() - 30_000;
    if (remaining <= 0) {
      setToken('');
      setContext(null);
      setPlatformSession(null);
      setOidcExpiresAt(null);
      setError(t('oidcExpired'));
      return;
    }
    const expiryTimer = window.setTimeout(() => {
      setToken('');
      setContext(null);
      setPlatformSession(null);
      setRecords([]);
      setOidcExpiresAt(null);
      setError(t('oidcExpired'));
    }, remaining);
    return () => window.clearTimeout(expiryTimer);
  }, [oidcExpiresAt, t]);

  useEffect(() => {
    if (!token) {
      setCheckingSession(false);
      return;
    }
    let active = true;
    setCheckingSession(true);
    // Never trust the role claim in an access token. The backend decides which
    // mutually exclusive security context is valid for THIS validated token.
    // OIDC platform tokens have no organization_id, so municipal context is 403.
    const municipal = getContext(token).catch(() => null);
    const platform = browserOidc?.mode === 'Oidc'
      ? getPlatformSession(token).catch(() => null)
      : Promise.resolve(null);
    void Promise.all([municipal, platform]).then(([municipalContext, operator]) => {
      if (!active) return;
      setCheckingSession(false);
      if (municipalContext && !operator) {
        setPlatformSession(null);
        setContext(municipalContext);
        setPage('dashboard');
        if (window.location.pathname === '/platform')
          window.history.replaceState(window.history.state, '', '/');
        setError('');
      } else if (operator && !municipalContext) {
        setContext(null);
        setPlatformSession(operator);
        setPage('platform');
        setError('');
      } else {
        // Both success (ambiguous) and both denied are fail-closed.
        setContext(null);
        setPlatformSession(null);
        setError(t('invalidToken'));
      }
    });
    return () => { active = false; };
  }, [token, browserOidc?.mode, t]);

  // Recheck a platform session on focus. Revocation in PostgreSQL denies the
  // next protected request, even if the external access token has not expired.
  useEffect(() => {
    if (!token || !platformSession || browserOidc?.mode !== 'Oidc') return;
    let active = true;
    const recheck = () => {
      void getPlatformSession(token).catch(() => {
        if (!active) return;
        setPlatformSession(null);
        setPage('dashboard');
        setError(t('invalidToken'));
        if (window.location.pathname === '/platform')
          window.history.replaceState(window.history.state, '', '/');
      });
    };
    window.addEventListener('focus', recheck);
    return () => {
      active = false;
      window.removeEventListener('focus', recheck);
    };
  }, [token, platformSession, browserOidc?.mode, t]);

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

  const loadAdminModules = useCallback(async () => {
    if (!token || !canAdmin) return;
    setLoadingAdmin(true);
    try {
      const [modules, memberships] = await Promise.all([
        getAdminModules(token), getAdminMemberships(token)
      ]);
      setAdminModules(modules);
      setAdminMemberships(memberships);
      setError('');
    } catch {
      setError(t('serverError'));
    } finally {
      setLoadingAdmin(false);
    }
  }, [token, canAdmin, t]);

  useEffect(() => {
    if (page === 'admin' && canAdmin) void loadAdminModules();
  }, [page, canAdmin, loadAdminModules]);

  async function toggleAdminModule(key: string, enabled: boolean) {
    if (!token || !canAdmin || savingAdmin) return;
    setSavingAdmin(true);
    setError('');
    try {
      await setAdminModule(token, key, enabled);
      const [modules, nextContext] = await Promise.all([getAdminModules(token), getContext(token)]);
      setAdminModules(modules);
      setContext(nextContext);
      setNotice(t('moduleUpdated'));
    } catch {
      setError(t('serverError'));
    } finally {
      setSavingAdmin(false);
    }
  }

  async function changeMembership(subject: string, role: 'Reader' | 'Officer', enabled: boolean): Promise<boolean> {
    if (!token || !canAdmin || savingMembership) return false;
    setSavingMembership(true);
    setError('');
    try {
      await setAdminMembership(token, role, subject, enabled);
      setAdminMemberships(await getAdminMemberships(token));
      setNotice(t('membershipUpdated'));
      return true;
    } catch {
      setError(t('serverError'));
      return false;
    } finally {
      setSavingMembership(false);
    }
  }

  async function assignMembership(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const subject = memberSubject.trim();
    if (!subject || subject.length > 160 || subject !== memberSubject) return;
    if (await changeMembership(subject, memberRole, true)) setMemberSubject('');
  }

  function enter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (tokenInput.trim()) {
      setError('');
      setToken(tokenInput.trim());
      setPage('dashboard');
    }
  }

  function startOidc() {
    if (!browserOidc?.enabled) return;
    setError('');
    void beginOidcLogin(browserOidc).catch(() => setError(t('oidcError')));
  }

  function logout() {
    clearPendingOidc();
    setOidcExpiresAt(null);
    setToken('');
    setTokenInput('');
    setContext(null);
    setPlatformSession(null);
    setCheckingSession(false);
    setRecords([]);
    setAdminModules([]);
    setAdminMemberships([]);
    setMemberSubject('');
    setPage('dashboard');
    setError('');
    if (window.location.pathname === '/platform')
      window.history.replaceState(window.history.state, '', '/');
  }

  async function navigatePlatform() {
    if (!token || !platformSession || browserOidc?.mode !== 'Oidc') return;
    try {
      // Revalidate before navigating; a visible menu is never an authorization.
      await getPlatformSession(token);
      setPage('platform');
      setMenuOpen(false);
      window.history.pushState(window.history.state, '', '/platform');
    } catch {
      setPlatformSession(null);
      setPage('dashboard');
      setError(t('invalidToken'));
      if (window.location.pathname === '/platform')
        window.history.replaceState(window.history.state, '', '/');
    }
  }

  function navigate(next: Page) {
    if (next === 'protocol' && !protocolEnabled) return;
    if (next === 'admin' && !canAdmin) return;
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

  if (platformSession && !context && !checkingSession && browserOidc?.mode === 'Oidc') {
    return (
      <div className="min-h-screen bg-background text-foreground md:flex">
        {menuOpen && <button aria-label={t('closeMenu')} className="fixed inset-0 z-20 bg-slate-950/40 md:hidden" onClick={() => setMenuOpen(false)} />}
        <aside className={cn('fixed inset-y-0 left-0 z-30 flex w-64 -translate-x-full flex-col border-r border-border bg-card px-4 py-6 transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0', menuOpen && 'translate-x-0')}>
          <Brand />
          <p className="mt-10 px-3 text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">{t('workspace')}</p>
          <nav aria-label="Navigazione principale" className="mt-3 flex flex-col gap-2">
            <Button variant="default" className="justify-start" onClick={() => void navigatePlatform()}>
              <LockKeyhole className="h-4 w-4" aria-hidden="true" />{t('platformNavigation')}
            </Button>
          </nav>
          <div className="mt-auto rounded-lg bg-muted p-4">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck className="h-4 w-4 text-teal-500" aria-hidden="true" />{t('platformScope')}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{t('platformRestricted')}</p>
          </div>
        </aside>

        <div className="min-w-0 flex-1">
          <header className="sticky top-0 z-10 flex min-h-20 items-center justify-between gap-3 border-b border-border bg-card/95 px-4 backdrop-blur sm:px-8">
            <div className="flex min-w-0 items-center gap-3">
              <Button variant="ghost" size="icon" className="md:hidden" aria-label={t('menu')} onClick={() => setMenuOpen(true)}>
                <Menu className="h-5 w-5" aria-hidden="true" />
              </Button>
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold sm:text-lg">{t('platformNavigation')}</div>
                <div className="text-xs text-muted-foreground">{t('platformScope')}</div>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {controls}
              <Button variant="ghost" size="sm" onClick={logout}>
                <LogOut className="h-4 w-4" aria-hidden="true" /><span className="hidden sm:inline">{t('signOut')}</span>
              </Button>
            </div>
          </header>
          <main className="mx-auto max-w-7xl space-y-7 px-4 py-8 sm:px-8">
            <p className="text-sm font-semibold text-teal-600 dark:text-teal-400">{t('overview')} / {t('platformNavigation')}</p>
            <h1 className="text-3xl font-bold tracking-tight">{t('platformTitle')}</h1>
            <p className="text-sm text-muted-foreground">{t('platformDescription')}</p>
            {error && <div role="alert" className="rounded-md border border-rose-300 p-3 text-sm text-rose-700">{error}</div>}
            <Card className="max-w-2xl">
              <CardHeader><CardTitle>{t('platformRoleTitle')}</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <p className="font-semibold">Superadmin</p>
                <p className="text-sm text-muted-foreground">{t('platformRestricted')}</p>
              </CardContent>
            </Card>
          </main>
        </div>
      </div>
    );
  }

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
              <p className="text-sm text-muted-foreground">
                {browserOidc?.mode === 'Oidc' ? t('oidcHelp') : t('tokenHelp')}
              </p>
            </CardHeader>
            <CardContent>
              {checkingSession ? (
                <p role="status" className="text-sm text-muted-foreground">{t('loading')}</p>
              ) : browserOidc === null ? (
                <p role="status" className="text-sm text-muted-foreground">{t('loading')}</p>
              ) : browserOidc.mode === 'DevelopmentJwt' ? (
              <form onSubmit={enter} className="space-y-4">
                <div>
                  <label htmlFor="jwt" className="mb-2 block text-sm font-medium">{t('tokenLabel')}</label>
                  <input id="jwt" type="password" autoComplete="off" spellCheck={false}
                    className="h-11 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500"
                    value={tokenInput} onChange={event => setTokenInput(event.target.value)}
                    placeholder={t('tokenPlaceholder')} required />
                </div>

                <Button className="w-full" type="submit">{t('useToken')} <ArrowRight aria-hidden="true" className="h-4 w-4" /></Button>
              </form>
              ) : browserOidc.enabled ? (
                <Button className="w-full" type="button" onClick={startOidc}>
                  {t('oidcSignIn')} <ArrowRight aria-hidden="true" className="h-4 w-4" />
                </Button>
              ) : <p className="text-sm text-muted-foreground">{t('oidcNotConfigured')}</p>}
              {error && <p role="alert" className="mt-3 text-sm text-rose-600">{error}</p>}
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
          {canAdmin && (
            <Button variant={page === 'admin' ? 'default' : 'ghost'} className="justify-start" onClick={() => navigate('admin')}>
              <Settings2 className="h-4 w-4" aria-hidden="true" />{t('administration')}
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
              <p className="text-sm font-semibold text-teal-600 dark:text-teal-400">{t('overview')} / {page === 'dashboard' ? t('dashboard') : page === 'admin' ? t('administration') : t('protocol')}</p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight">{page === 'dashboard' ? t('welcome') : page === 'admin' ? t('administration') : t('protocol')}</h1>
              <p className="mt-2 text-sm text-muted-foreground">{page === 'dashboard' ? t('subtitle') : page === 'admin' ? t('adminModulesDesc') : t('protocolDesc')}</p>
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
          ) : page === 'admin' ? (
            <>
            <Card className="max-w-3xl">
              <CardHeader>
                <CardTitle>{t('adminModulesTitle')}</CardTitle>
                <p className="text-sm text-muted-foreground">{t('adminModulesDesc')}</p>
              </CardHeader>
              <CardContent>
                {loadingAdmin ? <p className="text-sm text-muted-foreground">{t('loading')}</p> :
                  adminModules.length === 0 ? <p className="text-sm text-muted-foreground">{t('noModules')}</p> :
                  <ul className="divide-y divide-border">
                    {adminModules.map(module => (
                      <li key={module.key} className="flex flex-wrap items-center justify-between gap-3 py-4">
                        <div>
                          <p className="font-semibold">{module.key === 'protocol' ? t('protocol') : module.key}</p>
                          <p className="text-sm text-muted-foreground">{module.enabled ? t('moduleActive') : t('moduleInactive')}</p>
                        </div>
                        <Button disabled={savingAdmin} variant={module.enabled ? 'outline' : 'default'}
                          aria-label={module.enabled ? t('disableProtocol') : t('enableProtocol')}
                          onClick={() => void toggleAdminModule(module.key, !module.enabled)}>
                          {module.enabled ? t('disableProtocol') : t('enableProtocol')}
                        </Button>
                      </li>
                    ))}
                  </ul>}
              </CardContent>
            </Card>
            <Card className="max-w-3xl">
              <CardHeader>
                <CardTitle>{t('municipalMembers')}</CardTitle>
                <p className="text-sm text-muted-foreground">{t('membershipHelp')}</p>
              </CardHeader>
              <CardContent className="space-y-5">
                <form onSubmit={event => void assignMembership(event)}
                  className="flex flex-col items-start gap-3 sm:flex-row sm:items-end">
                  <div className="w-full flex-1">
                    <label htmlFor="idp-member-subject" className="mb-2 block text-sm font-medium">{t('memberSubject')}</label>
                    <input id="idp-member-subject" required maxLength={160}
                      value={memberSubject} onChange={event => setMemberSubject(event.target.value)}
                      className="h-11 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500"
                      autoComplete="off" spellCheck={false} />
                  </div>
                  <div className="w-full sm:w-32">
                    <label htmlFor="member-role" className="mb-2 block text-sm font-medium">{t('memberRole')}</label>
                    <select id="member-role" value={memberRole}
                      onChange={event => setMemberRole(event.target.value as 'Reader' | 'Officer')}
                      className="h-11 w-full rounded-md border border-border bg-background px-3 text-sm">
                      <option value="Reader">Reader</option>
                      <option value="Officer">Officer</option>
                    </select>
                  </div>
                  <Button disabled={savingMembership || loadingAdmin} type="submit">{t('assignMembership')}</Button>
                </form>
                {loadingAdmin ? <p className="text-sm text-muted-foreground">{t('loading')}</p> :
                  adminMemberships.length === 0 ? <p className="text-sm text-muted-foreground">{t('noMembers')}</p> :
                  <ul className="divide-y divide-border">
                    {adminMemberships.map(member => (
                      <li key={member.subject + ':' + member.role}
                        className="flex flex-wrap items-center justify-between gap-3 py-3">
                        <div className="min-w-0">
                          <p className="break-all text-sm font-semibold">{member.subject}</p>
                          <p className="text-sm text-muted-foreground">{member.role} · {member.enabled ? t('moduleActive') : t('moduleInactive')}</p>
                          {member.issuer && (
                            <p className="break-all text-xs text-muted-foreground" title={t('memberIssuer')}>
                              {member.issuer}
                            </p>
                          )}
                        </div>
                        {member.role !== 'Admin' && (member.role === 'Officer' || member.role === 'Reader') && (
                          <Button type="button" disabled={savingMembership} variant="outline"
                            aria-label={member.enabled ?
                              t('deactivateMembership', { role: member.role, subject: member.subject }) :
                              t('reactivateMembership', { role: member.role, subject: member.subject })}
                            onClick={() => void changeMembership(member.subject, member.role as 'Reader' | 'Officer', !member.enabled)}>
                            {member.enabled ? t('deactivate') : t('reactivate')}
                          </Button>
                        )}
                      </li>
                    ))}
                  </ul>}
              </CardContent>
            </Card>
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
