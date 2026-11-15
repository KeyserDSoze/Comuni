import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

void i18n.use(initReactI18next).init({
  resources: {
    it: { translation: {
      appName: 'Comuni', appTagline: 'La piattaforma digitale per gli enti locali',
      dashboard: 'Dashboard', protocol: 'Protocollo', overview: 'Panoramica',
      services: 'Servizi attivi', access: 'Accesso tecnico', tokenHelp: 'Inserisci un JWT firmato per la tua organization. Il token resta solo nella memoria di questa pagina.',
      tokenLabel: 'Token JWT di sviluppo', tokenPlaceholder: 'Incolla il JWT generato dallo script locale',
      useToken: 'Usa token', signOut: 'Esci', workspace: 'Spazio di lavoro',
      welcome: 'Benvenuto nel tuo Comune digitale', subtitle: 'Un unico accesso ai moduli, con sicurezza e dati separati per ogni ente.',
      modules: 'Moduli disponibili', role: 'Ruoli', currentOrg: 'Organization corrente',
      noModules: 'Nessun modulo abilitato per questa organization.', protocolDesc: 'Metadati dei documenti nel modulo dimostrativo.',
      openModule: 'Apri modulo', register: 'Registra documento', subject: 'Oggetto del documento',
      subjectPlaceholder: 'Es. Richiesta certificato', save: 'Salva documento', cancel: 'Annulla',
      records: 'Documenti recenti', noRecords: 'Nessun documento ancora registrato.',
      created: 'Documento registrato.', loading: 'Caricamento…', invalidToken: 'Impossibile verificare il token o caricare il contesto.',
      serverError: 'Operazione non riuscita. Verifica i permessi e la connessione.',
      demoNotice: 'Versione dimostrativa: non è un protocollo informatico a norma.',
      secure: 'Separazione dei dati per Comune', appStatus: 'Piattaforma operativa',
      lang: 'Lingua', theme: 'Tema', menu: 'Apri menu', closeMenu: 'Chiudi menu',
      home: 'Home', onlyEnabled: 'La navigazione mostra solo i moduli abilitati.',
      integration: 'Pronta per estensioni modulari', context: 'Contesto organizzativo'
    } },
    en: { translation: {
      appName: 'Comuni', appTagline: 'Digital services for local authorities',
      dashboard: 'Dashboard', protocol: 'Protocol', overview: 'Overview',
      services: 'Active services', access: 'Technical access', tokenHelp: 'Enter a signed JWT for your organization. This token is held only in page memory.',
      tokenLabel: 'Development JWT token', tokenPlaceholder: 'Paste a locally generated JWT',
      useToken: 'Use token', signOut: 'Sign out', workspace: 'Workspace',
      welcome: 'Welcome to your digital municipality', subtitle: 'One home for modular services, secure roles and organization-scoped data.',
      modules: 'Available modules', role: 'Roles', currentOrg: 'Current organization',
      noModules: 'No modules enabled for this organization.', protocolDesc: 'Document metadata in the demonstration module.',
      openModule: 'Open module', register: 'Register document', subject: 'Document subject',
      subjectPlaceholder: 'E.g. Certificate request', save: 'Save document', cancel: 'Cancel',
      records: 'Recent documents', noRecords: 'No documents have been registered.',
      created: 'Document registered.', loading: 'Loading…', invalidToken: 'Unable to verify token or load context.',
      serverError: 'Operation failed. Check permissions and connectivity.',
      demoNotice: 'Demonstration only: not a legally compliant protocol registry.',
      secure: 'Data segregation by municipality', appStatus: 'Platform available',
      lang: 'Language', theme: 'Theme', menu: 'Open menu', closeMenu: 'Close menu',
      home: 'Home', onlyEnabled: 'Navigation shows only enabled modules.',
      integration: 'Ready for modular extensions', context: 'Organization context'
    } }
  },
  lng: 'it',
  fallbackLng: 'it',
  interpolation: { escapeValue: false }
});

export default i18n;
